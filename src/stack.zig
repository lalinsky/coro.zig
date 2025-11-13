const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const windows = std.os.windows;

pub const page_size = std.heap.page_size_min;

pub const StackInfo = extern struct {
    _fiber_data: u64 = 0, // Windows only (TEB offset 0x20) TODO: not part of stack, but convenient to have here for now
    allocation_ptr: [*]align(page_size) u8, // deallocation_stack on Windows (TEB offset 0x1478)
    base: usize, // stack_base on Windows (TEB offset 0x08)
    limit: usize, // stack_limit on Windows (TEB offset 0x10)
    allocation_len: usize,
    valgrind_stack_id: usize = 0,
};

pub const StackAllocator = struct {
    ptr: ?*anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        alloc: *const fn (
            ptr: ?*anyopaque,
            info: *StackInfo,
            maximum_size: usize,
            committed_size: usize,
        ) error{OutOfMemory}!void,

        free: *const fn (
            ptr: ?*anyopaque,
            info: StackInfo,
        ) void,
    };

    pub fn alloc(self: StackAllocator, info: *StackInfo, maximum_size: usize, committed_size: usize) error{OutOfMemory}!void {
        return self.vtable.alloc(self.ptr, info, maximum_size, committed_size);
    }

    pub fn free(self: StackAllocator, info: StackInfo) void {
        return self.vtable.free(self.ptr, info);
    }
};

const default_vtable = StackAllocator.VTable{
    .alloc = defaultAlloc,
    .free = defaultFree,
};

fn defaultAlloc(_: ?*anyopaque, info: *StackInfo, maximum_size: usize, committed_size: usize) error{OutOfMemory}!void {
    return stackAlloc(info, maximum_size, committed_size);
}

fn defaultFree(_: ?*anyopaque, info: StackInfo) void {
    return stackFree(info);
}

pub var default_stack_allocator = StackAllocator{
    .ptr = null,
    .vtable = &default_vtable,
};

pub fn stackAlloc(info: *StackInfo, maximum_size: usize, committed_size: usize) error{OutOfMemory}!void {
    if (builtin.os.tag == .windows) {
        try stackAllocWindows(info, maximum_size, committed_size);
    } else {
        try stackAllocPosix(info, maximum_size, committed_size);
    }

    // Register stack with valgrind
    if (builtin.mode == .Debug and builtin.valgrind_support) {
        const stack_slice: [*]u8 = @ptrFromInt(info.limit);
        info.valgrind_stack_id = std.valgrind.stackRegister(stack_slice[0 .. info.base - info.limit]);
    }
}

fn stackAllocPosix(info: *StackInfo, maximum_size: usize, committed_size: usize) error{OutOfMemory}!void {
    // Ensure we allocate at least 2 pages (guard + usable space)
    const min_pages = 2;
    const adjusted_size = @max(maximum_size, page_size * min_pages);

    const size = std.math.ceilPowerOfTwo(usize, adjusted_size) catch |err| {
        std.log.err("Failed to calculate stack size: {}", .{err});
        return error.OutOfMemory;
    };

    // Reserve address space with PROT_NONE (like Linux POC for lazy commit)
    const allocation = posix.mmap(
        null, // Address hint (null for system to choose)
        size,
        posix.PROT.NONE, // Reserved but not accessible
        .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
        -1, // File descriptor (not applicable)
        0, // Offset within the file (not applicable)
    ) catch |err| {
        std.log.err("Failed to allocate stack memory: {}", .{err});
        return error.OutOfMemory;
    };
    errdefer posix.munmap(allocation);

    // Guard page stays as PROT_NONE (first page)

    // Round committed size up to page boundary
    const commit_size = std.mem.alignForward(usize, committed_size, page_size);

    // Commit initial portion at top of stack
    const stack_top = @intFromPtr(allocation.ptr) + size;
    const initial_commit_start = stack_top - commit_size;
    const initial_region: [*]align(page_size) u8 = @ptrFromInt(initial_commit_start);
    posix.mprotect(initial_region[0..commit_size], posix.PROT.READ | posix.PROT.WRITE) catch |err| {
        std.log.err("Failed to commit initial stack region: {}", .{err});
        return error.OutOfMemory;
    };

    // Stack layout (grows downward from high to low addresses):
    // [guard_page (PROT_NONE)][uncommitted (PROT_NONE)][committed (READ|WRITE)]
    // ^                                                 ^                       ^
    // allocation_ptr                                    limit                   base (allocation_ptr + allocation_len)
    info.* = .{
        .allocation_ptr = allocation.ptr,
        .base = stack_top, // Top of stack (high address)
        .limit = initial_commit_start, // Bottom of committed region
        .allocation_len = allocation.len,
    };
}

pub fn stackFree(info: StackInfo) void {
    // Deregister stack from valgrind
    if (builtin.mode == .Debug and builtin.valgrind_support) {
        if (info.valgrind_stack_id != 0) {
            std.valgrind.stackDeregister(info.valgrind_stack_id);
        }
    }

    if (builtin.os.tag == .windows) {
        return stackFreeWindows(info);
    } else {
        return stackFreePosix(info);
    }
}

fn stackFreePosix(info: StackInfo) void {
    const allocation: []align(page_size) u8 = info.allocation_ptr[0..info.allocation_len];
    posix.munmap(allocation);
}

pub fn stackExtend(info: *StackInfo) error{StackOverflow}!void {
    if (builtin.os.tag == .windows) {
        try stackExtendWindows(info);
    } else {
        try stackExtendPosix(info);
    }

    // Notify valgrind of stack size change
    if (builtin.mode == .Debug and builtin.valgrind_support) {
        if (info.valgrind_stack_id != 0) {
            const stack_slice: [*]u8 = @ptrFromInt(info.limit);
            std.valgrind.stackChange(info.valgrind_stack_id, stack_slice[0 .. info.base - info.limit]);
        }
    }
}

/// Extend the committed stack region by a growth factor (1.5x current size).
/// Commits in 64KB chunks. For testing stack growth mechanism.
fn stackExtendPosix(info: *StackInfo) error{StackOverflow}!void {
    const chunk_size = 64 * 1024;
    const growth_factor_num = 3;
    const growth_factor_den = 2;

    // Calculate current committed size
    const current_committed = info.base - info.limit;

    // Calculate new committed size (1.5x current)
    const new_committed_size = (current_committed * growth_factor_num) / growth_factor_den;
    const additional_size = new_committed_size - current_committed;
    const size_to_commit = std.mem.alignForward(usize, additional_size, chunk_size);

    // Calculate new limit (stack grows downward from high to low address)
    const new_limit = if (info.limit >= size_to_commit) info.limit - size_to_commit else 0;

    // Check we don't overflow into guard page
    const guard_end = @intFromPtr(info.allocation_ptr) + page_size;
    if (new_limit < guard_end) {
        return error.StackOverflow;
    }

    // Commit the memory region (like Linux POC signal handler)
    const commit_start = std.mem.alignBackward(usize, new_limit, page_size);
    const commit_size = info.limit - commit_start;
    const addr: [*]align(page_size) u8 = @ptrFromInt(commit_start);
    posix.mprotect(addr[0..commit_size], posix.PROT.READ | posix.PROT.WRITE) catch {
        return error.StackOverflow;
    };

    // Update limit to new bottom of committed region
    info.limit = commit_start;
}

fn stackAllocWindows(info: *StackInfo, maximum_size: usize, committed_size: usize) error{OutOfMemory}!void {
    // Round committed size up to page boundary
    const commit_size = std.mem.alignForward(usize, committed_size, page_size);

    // Ensure we allocate at least 2 pages (guard + usable space)
    const min_pages = 2;
    const min_size = page_size * min_pages;

    // Need space for: guard page + committed region
    const needed_size = commit_size + page_size;
    const adjusted_size = @max(maximum_size, @max(min_size, needed_size));

    const max_size = std.math.ceilPowerOfTwo(usize, adjusted_size) catch |err| {
        std.log.err("Failed to calculate maximum stack size: {}", .{err});
        return error.OutOfMemory;
    };

    // Reserve the address space without committing physical memory
    const stack_mem = windows.VirtualAlloc(
        null, // Address hint (null for system to choose)
        max_size,
        windows.MEM_RESERVE,
        windows.PAGE_NOACCESS,
    ) catch |err| {
        std.log.err("Failed to reserve stack memory: {}", .{err});
        return error.OutOfMemory;
    };
    errdefer windows.VirtualFree(stack_mem, 0, windows.MEM_RELEASE);

    // Convert to aligned slice (VirtualAlloc returns 64KB-aligned memory)
    const allocation: []align(page_size) u8 = @alignCast(@as([*]u8, @ptrCast(stack_mem))[0..max_size]);
    const stack_addr = @intFromPtr(allocation.ptr);

    // Calculate the layout:
    // [uncommitted][guard_page][committed]
    const uncommitted_size = max_size - commit_size - page_size;
    const guard_start = stack_addr + uncommitted_size;
    const committed_start = guard_start + page_size;

    // Commit the guard page with PAGE_GUARD attribute
    // This will trigger a one-shot exception if accessed
    _ = windows.VirtualAlloc(
        @ptrFromInt(guard_start),
        page_size,
        windows.MEM_COMMIT,
        windows.PAGE_READWRITE | windows.PAGE_GUARD,
    ) catch |err| {
        std.log.err("Failed to commit guard page: {}", .{err});
        return error.OutOfMemory;
    };

    // Commit the requested portion of the usable stack space
    // The rest remains reserved but uncommitted at the bottom
    _ = windows.VirtualAlloc(
        @ptrFromInt(committed_start),
        commit_size,
        windows.MEM_COMMIT,
        windows.PAGE_READWRITE,
    ) catch |err| {
        std.log.err("Failed to commit stack memory: {}", .{err});
        return error.OutOfMemory;
    };

    const stack_top = stack_addr + max_size;

    // Stack layout (grows downward from high to low addresses):
    // [uncommitted][guard_page][committed_stack_space]
    // ^            ^           ^                       ^
    // allocation_ptr           limit                   base (allocation_ptr + allocation_len)
    info.* = .{
        .allocation_ptr = allocation.ptr,
        .base = stack_top, // Top of stack (high address)
        .limit = committed_start, // Bottom of committed stack (just after guard)
        .allocation_len = allocation.len,
    };
}

fn stackFreeWindows(info: StackInfo) void {
    windows.VirtualFree(info.allocation_ptr, 0, windows.MEM_RELEASE);
}

/// Extend the committed stack region by a growth factor (1.5x current size).
/// Commits in 64KB chunks. For testing stack growth mechanism.
fn stackExtendWindows(info: *StackInfo) error{StackOverflow}!void {
    const chunk_size = 64 * 1024;
    const growth_factor_num = 3;
    const growth_factor_den = 2;

    // Calculate current committed size
    const current_committed = info.base - info.limit;

    // Calculate new committed size (1.5x current)
    const new_committed_size = (current_committed * growth_factor_num) / growth_factor_den;
    const additional_size = new_committed_size - current_committed;
    const size_to_commit = std.mem.alignForward(usize, additional_size, chunk_size);

    // Calculate new limit (stack grows downward from high to low address)
    const new_limit = if (info.limit >= size_to_commit) info.limit - size_to_commit else 0;

    // Check we don't overflow into the allocation base
    const alloc_base = @intFromPtr(info.allocation_ptr);
    if (new_limit < alloc_base) {
        return error.StackOverflow;
    }

    // Calculate new guard page position (one page before new committed region)
    const new_guard_start = if (new_limit >= page_size) new_limit - page_size else alloc_base;
    if (new_guard_start < alloc_base) {
        return error.StackOverflow;
    }

    // Commit the new region
    const commit_start = std.mem.alignBackward(usize, new_limit, page_size);
    const commit_size = info.limit - commit_start;
    _ = windows.VirtualAlloc(
        @ptrFromInt(commit_start),
        commit_size,
        windows.MEM_COMMIT,
        windows.PAGE_READWRITE,
    ) catch {
        return error.StackOverflow;
    };

    // Update the guard page (commit with PAGE_GUARD)
    _ = windows.VirtualAlloc(
        @ptrFromInt(new_guard_start),
        page_size,
        windows.MEM_COMMIT,
        windows.PAGE_READWRITE | windows.PAGE_GUARD,
    ) catch {
        return error.StackOverflow;
    };

    // Update limit to new bottom of committed region
    info.limit = commit_start;
}

test "Stack: alloc/free" {
    const maximum_size = 8192;
    const committed_size = 1024;
    var stack: StackInfo = undefined;
    try stackAlloc(&stack, maximum_size, committed_size);
    defer stackFree(stack);

    // Verify allocation size is at least the requested size (rounded to power of 2 with min 2 pages)
    try std.testing.expect(stack.allocation_len >= maximum_size);

    // Verify base is at the top (high address)
    try std.testing.expect(stack.base > stack.limit);

    // Verify limit calculation based on platform
    // Note: committed_size gets rounded up to page boundary
    const commit_size_rounded = std.mem.alignForward(usize, committed_size, page_size);
    const expected_limit = switch (builtin.os.tag) {
        // On Windows: [uncommitted][guard][committed]
        // limit points to start of committed region
        .windows => @intFromPtr(stack.allocation_ptr) + stack.allocation_len - commit_size_rounded,
        // On POSIX: [guard][uncommitted][committed]
        // limit points to start of committed region
        else => @intFromPtr(stack.allocation_ptr) + stack.allocation_len - commit_size_rounded,
    };
    try std.testing.expectEqual(expected_limit, stack.limit);

    // Verify base is at the top of the allocation
    try std.testing.expect(stack.base >= @intFromPtr(stack.allocation_ptr));
    try std.testing.expect(stack.base <= @intFromPtr(stack.allocation_ptr) + stack.allocation_len);
}

test "Stack: fully committed" {
    const size = 64 * 1024;
    var stack: StackInfo = undefined;
    try stackAlloc(&stack, size, size);
    defer stackFree(stack);

    // Verify allocation succeeded
    try std.testing.expect(stack.allocation_len >= size);
    try std.testing.expect(stack.base > stack.limit);

    // Verify base is at the top of the allocation
    try std.testing.expect(stack.base >= @intFromPtr(stack.allocation_ptr));
    try std.testing.expect(stack.base <= @intFromPtr(stack.allocation_ptr) + stack.allocation_len);
}

test "Stack: extend" {
    const maximum_size = 256 * 1024;
    const initial_commit = 64 * 1024;
    var stack: StackInfo = undefined;
    try stackAlloc(&stack, maximum_size, initial_commit);
    defer stackFree(stack);

    const initial_limit = stack.limit;
    const initial_committed = stack.base - stack.limit;

    // Extend by growth factor (1.5x)
    try stackExtend(&stack);

    // Verify limit moved down
    try std.testing.expect(stack.limit < initial_limit);

    // Verify committed size increased by ~50%
    const new_committed = stack.base - stack.limit;
    try std.testing.expect(new_committed > initial_committed);
    try std.testing.expect(new_committed >= initial_committed * 14 / 10); // At least 1.4x due to rounding

    // Verify we can write to the extended region
    const extended_region: [*]u8 = @ptrFromInt(stack.limit);
    @memset(extended_region[0..1024], 0xAA);
}
