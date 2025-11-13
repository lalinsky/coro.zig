const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const windows = std.os.windows;

pub const page_size = std.heap.page_size_min;

pub const StackPosix = struct {
    allocation: []align(page_size) u8,
    base: usize,
    limit: usize,
    valgrind_stack_id: usize,

    pub fn alloc(maximum_size: usize, committed_size: usize) error{OutOfMemory}!*@This() {
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

        // Place the Stack metadata at the top of the allocation (high address)
        const self_ptr = std.mem.alignBackward(usize, stack_top - @sizeOf(@This()), @alignOf(@This()));
        const self: *@This() = @ptrFromInt(self_ptr);

        // Stack layout (grows downward from high to low addresses):
        // [guard_page (PROT_NONE)][uncommitted (PROT_NONE)][committed (READ|WRITE)][metadata]
        // ^                       ^                         ^                       ^
        // allocation              limit                      initial_commit_start   base
        self.* = .{
            .allocation = allocation,
            .base = self_ptr, // Top of stack (high address, where metadata is)
            .limit = initial_commit_start, // Bottom of committed region
            .valgrind_stack_id = 0,
        };

        // Register stack with valgrind
        if (builtin.mode == .Debug and builtin.valgrind_support) {
            const stack_slice: [*]u8 = @ptrFromInt(self.limit);
            self.valgrind_stack_id = std.valgrind.stackRegister(stack_slice[0 .. self.base - self.limit]);
        }

        return self;
    }

    pub fn free(self: *@This()) void {
        // Deregister stack from valgrind
        if (builtin.mode == .Debug and builtin.valgrind_support) {
            if (self.valgrind_stack_id != 0) {
                std.valgrind.stackDeregister(self.valgrind_stack_id);
            }
        }
        posix.munmap(self.allocation);
    }

    /// Extend the committed stack region by a growth factor (1.5x current size).
    /// Commits in 64KB chunks. For testing stack growth mechanism.
    pub fn extend(self: *@This()) error{StackOverflow}!void {
        const chunk_size = 64 * 1024;
        const growth_factor_num = 3;
        const growth_factor_den = 2;

        // Calculate current committed size
        const current_committed = self.base - self.limit;

        // Calculate new committed size (1.5x current)
        const new_committed_size = (current_committed * growth_factor_num) / growth_factor_den;
        const additional_size = new_committed_size - current_committed;
        const size_to_commit = std.mem.alignForward(usize, additional_size, chunk_size);

        // Calculate new limit (stack grows downward from high to low address)
        const new_limit = if (self.limit >= size_to_commit) self.limit - size_to_commit else 0;

        // Check we don't overflow into guard page
        const guard_end = @intFromPtr(self.allocation.ptr) + page_size;
        if (new_limit < guard_end) {
            return error.StackOverflow;
        }

        // Commit the memory region (like Linux POC signal handler)
        const commit_start = std.mem.alignBackward(usize, new_limit, page_size);
        const commit_size = self.limit - commit_start;
        const addr: [*]align(page_size) u8 = @ptrFromInt(commit_start);
        posix.mprotect(addr[0..commit_size], posix.PROT.READ | posix.PROT.WRITE) catch {
            return error.StackOverflow;
        };

        // Update limit to new bottom of committed region
        self.limit = commit_start;

        // Notify valgrind of stack size change
        if (builtin.mode == .Debug and builtin.valgrind_support) {
            if (self.valgrind_stack_id != 0) {
                const stack_slice: [*]u8 = @ptrFromInt(self.limit);
                std.valgrind.stackChange(self.valgrind_stack_id, stack_slice[0 .. self.base - self.limit]);
            }
        }
    }
};

pub const StackWindows = struct {
    allocation: []align(page_size) u8,
    base: usize,
    limit: usize,
    valgrind_stack_id: usize,

    pub fn alloc(maximum_size: usize, committed_size: usize) error{OutOfMemory}!*@This() {
        // Ensure we allocate at least 2 pages (guard + usable space)
        const min_pages = 2;
        const adjusted_size = @max(maximum_size, page_size * min_pages);

        const max_size = std.math.ceilPowerOfTwo(usize, adjusted_size) catch |err| {
            std.log.err("Failed to calculate maximum stack size: {}", .{err});
            return error.OutOfMemory;
        };

        // Round committed size up to page boundary
        const commit_size = std.mem.alignForward(usize, committed_size, page_size);

        // Ensure committed size doesn't exceed available space (max_size - guard - metadata)
        if (commit_size > max_size - page_size) {
            std.log.err("Committed size ({}) exceeds available space ({})", .{ commit_size, max_size - page_size });
            return error.OutOfMemory;
        }

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
        // [uncommitted][guard_page][committed][metadata]
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

        // Place the Stack metadata at the top of the allocation (high address)
        const self_ptr = std.mem.alignBackward(usize, stack_addr + max_size - @sizeOf(@This()), @alignOf(@This()));
        const self: *@This() = @ptrFromInt(self_ptr);

        // Stack layout (grows downward from high to low addresses):
        // [uncommitted][guard_page][committed_stack_space][metadata]
        // ^            ^           ^                       ^
        // allocation   guard       limit                   base
        self.* = .{
            .allocation = allocation,
            .base = self_ptr, // Top of stack (high address, where metadata is)
            .limit = committed_start, // Bottom of committed stack (just after guard)
            .valgrind_stack_id = 0,
        };

        // Register stack with valgrind
        if (builtin.mode == .Debug and builtin.valgrind_support) {
            const stack_slice: [*]u8 = @ptrFromInt(self.limit);
            self.valgrind_stack_id = std.valgrind.stackRegister(stack_slice[0 .. self.base - self.limit]);
        }

        return self;
    }

    pub fn free(self: *@This()) void {
        // Deregister stack from valgrind
        if (builtin.mode == .Debug and builtin.valgrind_support) {
            if (self.valgrind_stack_id != 0) {
                std.valgrind.stackDeregister(self.valgrind_stack_id);
            }
        }
        windows.VirtualFree(self.allocation.ptr, 0, windows.MEM_RELEASE);
    }

    /// Extend the committed stack region by a growth factor (1.5x current size).
    /// Commits in 64KB chunks. For testing stack growth mechanism.
    pub fn extend(self: *@This()) error{StackOverflow}!void {
        const chunk_size = 64 * 1024;
        const growth_factor_num = 3;
        const growth_factor_den = 2;

        // Calculate current committed size
        const current_committed = self.base - self.limit;

        // Calculate new committed size (1.5x current)
        const new_committed_size = (current_committed * growth_factor_num) / growth_factor_den;
        const additional_size = new_committed_size - current_committed;
        const size_to_commit = std.mem.alignForward(usize, additional_size, chunk_size);

        // Calculate new limit (stack grows downward from high to low address)
        const new_limit = if (self.limit >= size_to_commit) self.limit - size_to_commit else 0;

        // Check we don't overflow into the allocation base
        const alloc_base = @intFromPtr(self.allocation.ptr);
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
        const commit_size = self.limit - commit_start;
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
        self.limit = commit_start;

        // Notify valgrind of stack size change
        if (builtin.mode == .Debug and builtin.valgrind_support) {
            if (self.valgrind_stack_id != 0) {
                const stack_slice: [*]u8 = @ptrFromInt(self.limit);
                std.valgrind.stackChange(self.valgrind_stack_id, stack_slice[0 .. self.base - self.limit]);
            }
        }
    }
};

pub const Stack = switch (builtin.os.tag) {
    .windows => StackWindows,
    else => StackPosix,
};

test "Stack: alloc/free" {
    const maximum_size = 8192;
    const committed_size = 1024;
    const stack = try Stack.alloc(maximum_size, committed_size);
    defer stack.free();

    // Verify allocation size is at least the requested size (rounded to power of 2 with min 2 pages)
    try std.testing.expect(stack.allocation.len >= maximum_size);

    // Verify base is at the top (high address)
    try std.testing.expect(stack.base > stack.limit);

    // Verify limit calculation based on platform
    // Note: committed_size gets rounded up to page boundary
    const commit_size_rounded = std.mem.alignForward(usize, committed_size, page_size);
    const expected_limit = switch (builtin.os.tag) {
        // On Windows: [uncommitted][guard][committed][metadata]
        // limit points to start of committed region
        .windows => @intFromPtr(stack.allocation.ptr) + stack.allocation.len - commit_size_rounded,
        // On POSIX: [guard][uncommitted][committed][metadata]
        // limit points to start of committed region
        else => @intFromPtr(stack.allocation.ptr) + stack.allocation.len - commit_size_rounded,
    };
    try std.testing.expectEqual(expected_limit, stack.limit);

    // Verify base is within the allocation
    try std.testing.expect(stack.base >= @intFromPtr(stack.allocation.ptr));
    try std.testing.expect(stack.base < @intFromPtr(stack.allocation.ptr) + stack.allocation.len);
}

test "Stack: fully committed" {
    const size = 64 * 1024;
    const stack = try Stack.alloc(size, size);
    defer stack.free();

    // Verify allocation succeeded
    try std.testing.expect(stack.allocation.len >= size);
    try std.testing.expect(stack.base > stack.limit);

    // Verify base is within the allocation
    try std.testing.expect(stack.base >= @intFromPtr(stack.allocation.ptr));
    try std.testing.expect(stack.base < @intFromPtr(stack.allocation.ptr) + stack.allocation.len);
}

test "Stack: extend" {
    const maximum_size = 256 * 1024;
    const initial_commit = 64 * 1024;
    const stack = try Stack.alloc(maximum_size, initial_commit);
    defer stack.free();

    const initial_limit = stack.limit;
    const initial_committed = stack.base - stack.limit;

    // Extend by growth factor (1.5x)
    try stack.extend();

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
