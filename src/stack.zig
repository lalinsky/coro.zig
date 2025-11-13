const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const windows = std.os.windows;
const coroutines = @import("coroutines.zig");

pub const page_size = std.heap.page_size_min;

// Stack growth signal handler state (POSIX only)
threadlocal var altstack_installed: bool = false;
threadlocal var altstack_mem: ?[]u8 = null;
var signal_handler_refcount: std.atomic.Value(usize) = std.atomic.Value(usize).init(0);
var old_sigaction: posix.Sigaction = undefined;

// Platform-specific macros for declaring future mprotect permissions
// NetBSD PROT_MPROTECT: Required when PaX MPROTECT is enabled to allow permission escalation
// FreeBSD PROT_MAX: Optional security feature to restrict maximum permissions
// See: https://man.netbsd.org/mmap.2 and https://man.freebsd.org/mmap.2
inline fn PROT_MAX_FUTURE(prot: u32) u32 {
    return switch (builtin.os.tag) {
        .netbsd => prot << 3, // PROT_MPROTECT
        .freebsd => prot << 16, // PROT_MAX
        else => 0,
    };
}

// Windows ntdll.dll functions for stack management
const INITIAL_TEB = extern struct {
    OldStackBase: windows.PVOID,
    OldStackLimit: windows.PVOID,
    StackBase: windows.PVOID,
    StackLimit: windows.PVOID,
    StackAllocationBase: windows.PVOID,
};

extern "ntdll" fn RtlCreateUserStack(
    CommittedStackSize: windows.SIZE_T,
    MaximumStackSize: windows.SIZE_T,
    ZeroBits: windows.ULONG_PTR,
    PageSize: windows.SIZE_T,
    ReserveAlignment: windows.ULONG_PTR,
    InitialTeb: *INITIAL_TEB,
) callconv(.winapi) windows.NTSTATUS;

extern "ntdll" fn RtlFreeUserStack(
    StackAllocationBase: windows.PVOID,
) callconv(.winapi) void;

pub const StackInfo = extern struct {
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

    if (builtin.mode == .Debug and builtin.valgrind_support) {
        const stack_slice: [*]u8 = @ptrFromInt(info.limit);
        info.valgrind_stack_id = std.valgrind.stackRegister(stack_slice[0 .. info.base - info.limit]);
    }
}

fn stackAllocPosix(info: *StackInfo, maximum_size: usize, committed_size: usize) error{OutOfMemory}!void {
    // Ensure we allocate at least 2 pages (guard + usable space)
    const min_pages = 2;
    // Add guard page to maximum_size to get total allocation size
    const adjusted_size = @max(maximum_size + page_size, page_size * min_pages);

    const size = std.math.ceilPowerOfTwo(usize, adjusted_size) catch |err| {
        std.log.err("Failed to calculate stack size: {}", .{err});
        return error.OutOfMemory;
    };

    // Reserve address space with PROT_NONE
    // On NetBSD/FreeBSD, we must declare future permissions upfront for security policies
    const prot_flags = posix.PROT.NONE | PROT_MAX_FUTURE(posix.PROT.READ | posix.PROT.WRITE);

    const allocation = posix.mmap(
        null, // Address hint (null for system to choose)
        size,
        prot_flags,
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

    // Validate that committed size doesn't exceed available space (minus guard page)
    if (commit_size > size - page_size) {
        std.log.err("Committed size ({d}) exceeds maximum size ({d}) after alignment", .{ commit_size, size - page_size });
        return error.OutOfMemory;
    }

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
    // ^                                                ^                       ^
    // allocation_ptr                                   limit                   base (allocation_ptr + allocation_len)
    info.* = .{
        .allocation_ptr = allocation.ptr,
        .base = stack_top,
        .limit = initial_commit_start,
        .allocation_len = allocation.len,
    };
}

pub fn stackFree(info: StackInfo) void {
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

    if (builtin.mode == .Debug and builtin.valgrind_support) {
        if (info.valgrind_stack_id != 0) {
            const stack_slice: [*]u8 = @ptrFromInt(info.limit);
            std.valgrind.stackChange(info.valgrind_stack_id, stack_slice[0 .. info.base - info.limit]);
        }
    }
}

/// Extend the committed stack region by a growth factor (1.5x current size).
/// Commits in 64KB chunks.
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
    // Check if we have enough uncommitted space
    if (size_to_commit > info.limit) {
        return error.StackOverflow;
    }
    const new_limit = info.limit - size_to_commit;

    // Check we don't overflow into guard page
    const guard_end = @intFromPtr(info.allocation_ptr) + page_size;
    if (new_limit < guard_end) {
        return error.StackOverflow;
    }

    // Commit the memory region
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
    // Round sizes up to page boundary
    const commit_size = std.mem.alignForward(usize, committed_size, page_size);
    const max_size = std.mem.alignForward(usize, maximum_size, page_size);

    // Validate that committed size doesn't exceed maximum size
    if (commit_size > max_size) {
        std.log.err("Committed size ({d}) exceeds maximum size ({d}) after alignment", .{ commit_size, max_size });
        return error.OutOfMemory;
    }

    // Use RtlCreateUserStack for automatic stack growth via PAGE_GUARD
    const ALLOCATION_GRANULARITY = 65536; // 64KB on Windows
    var initial_teb: INITIAL_TEB = undefined;

    const status = RtlCreateUserStack(
        commit_size,
        max_size,
        0, // ZeroBits
        page_size,
        ALLOCATION_GRANULARITY,
        &initial_teb,
    );

    if (status != .SUCCESS) {
        std.log.err("RtlCreateUserStack failed with status: 0x{x}", .{@intFromEnum(status)});
        return error.OutOfMemory;
    }

    // Extract stack information from INITIAL_TEB
    // RtlCreateUserStack creates: [uncommitted][guard_page][committed]
    // and sets up automatic growth via PAGE_GUARD mechanism
    const stack_base = @intFromPtr(initial_teb.StackBase);
    const stack_limit = @intFromPtr(initial_teb.StackLimit);
    const alloc_base = @intFromPtr(initial_teb.StackAllocationBase);

    info.* = .{
        .allocation_ptr = @ptrCast(@alignCast(initial_teb.StackAllocationBase)),
        .base = stack_base,
        .limit = stack_limit,
        .allocation_len = stack_base - alloc_base,
    };
}

fn stackFreeWindows(info: StackInfo) void {
    RtlFreeUserStack(info.allocation_ptr);
}

/// Windows handles stack growth automatically via PAGE_GUARD mechanism
/// when using RtlCreateUserStack. This function should never be called.
fn stackExtendWindows(_: *StackInfo) error{StackOverflow}!void {
    unreachable;
}

/// Setup automatic stack growth via SIGSEGV handler for this thread.
/// This function is idempotent - safe to call multiple times per thread.
///
/// On first call (any thread): Installs global SIGSEGV signal handler
/// On every call: Sets up alternate signal stack for this thread if not already configured
/// On Windows: No-op (stack growth is automatic via PAGE_GUARD)
///
/// Must be called once per thread before using coroutines on that thread.
pub fn setupStackGrowth() !void {
    // Windows handles stack growth automatically
    if (builtin.os.tag == .windows) return;

    std.log.info("setupStackGrowth: Starting", .{});

    const altstack_size = switch (builtin.os.tag) {
        .linux => std.os.linux.SIGSTKSZ,
        else => std.c.SIGSTKSZ,
    };

    std.log.info("setupStackGrowth: SIGSTKSZ = {d}", .{altstack_size});

    // Setup alternate stack for this thread if not already done
    if (!altstack_installed) {
        std.log.info("setupStackGrowth: Allocating altstack", .{});
        const mem = try std.heap.page_allocator.alignedAlloc(u8, .fromByteUnits(page_size), altstack_size);
        errdefer std.heap.page_allocator.free(mem);

        var stack = posix.stack_t{
            .flags = 0,
            .sp = mem.ptr,
            .size = altstack_size,
        };

        std.log.info("setupStackGrowth: Calling sigaltstack", .{});
        posix.sigaltstack(&stack, null) catch |err| {
            std.log.err("setupStackGrowth: sigaltstack failed: {}", .{err});
            std.heap.page_allocator.free(mem);
            return err;
        };

        altstack_mem = mem;
        altstack_installed = true;
        std.log.info("setupStackGrowth: Altstack installed successfully", .{});
    } else {
        std.log.info("setupStackGrowth: Altstack already installed", .{});
    }

    // Install global signal handler (once per process)
    // Increment refcount; if this is the first caller, install the handler
    const prev_refcount = signal_handler_refcount.fetchAdd(1, .acquire);
    errdefer _ = signal_handler_refcount.fetchSub(1, .release);

    if (prev_refcount == 0) {
        std.log.info("setupStackGrowth: Installing SIGSEGV handler", .{});
        var sa = posix.Sigaction{
            .handler = .{ .sigaction = sigsegvHandler },
            .mask = posix.sigemptyset(),
            .flags = posix.SA.SIGINFO | posix.SA.ONSTACK | posix.SA.NODEFER,
        };

        posix.sigaction(posix.SIG.SEGV, &sa, &old_sigaction);
        std.log.info("setupStackGrowth: SIGSEGV handler installed successfully", .{});
    } else {
        std.log.info("setupStackGrowth: SIGSEGV handler already installed (refcount now: {d})", .{prev_refcount + 1});
    }

    std.log.info("setupStackGrowth: Complete", .{});
}

/// Cleanup stack growth handler state for this thread.
/// Disables the alternate stack and frees its memory.
/// Decrements the global signal handler refcount and uninstalls the handler when it reaches 0.
/// On Windows: No-op (nothing to clean up)
///
/// Should be called when a thread exits if setupStackGrowth() was called.
pub fn cleanupStackGrowth() void {
    // Windows has nothing to clean up
    if (builtin.os.tag == .windows) return;

    if (altstack_installed) {
        // Disable alternate stack
        var disable_stack = posix.stack_t{
            .flags = std.posix.system.SS.DISABLE,
            .sp = undefined,
            .size = 0,
        };
        posix.sigaltstack(&disable_stack, null) catch {
            // Best effort - can't do much if this fails
        };

        // Free the alternate stack memory
        if (altstack_mem) |mem| {
            std.heap.page_allocator.free(mem);
            altstack_mem = null;
        }

        altstack_installed = false;

        // Decrement refcount; if this was the last thread, uninstall the handler
        const prev_refcount = signal_handler_refcount.fetchSub(1, .release);
        if (prev_refcount == 1) {
            // We were the last thread - restore the old signal handler
            posix.sigaction(posix.SIG.SEGV, &old_sigaction, null);
        }
    }
}

/// Extract fault address from siginfo_t in a platform-agnostic way
inline fn getFaultAddress(info: *const posix.siginfo_t) usize {
    return @intFromPtr(switch (builtin.os.tag) {
        .linux => info.fields.sigfault.addr,
        .macos, .ios, .tvos, .watchos, .visionos => info.addr,
        .freebsd, .dragonfly => info.addr,
        .netbsd => info.info.reason.fault.addr,
        .solaris, .illumos => info.reason.fault.addr,
        else => @compileError("Stack growth not supported on this platform"),
    });
}

/// SIGSEGV signal handler for automatic stack growth.
/// This handler checks if the fault is within a coroutine's uncommitted stack region
/// and extends the stack if so. Real segmentation faults are re-raised.
fn sigsegvHandler(sig: c_int, info: *const posix.siginfo_t, _: ?*const anyopaque) callconv(.c) void {
    _ = sig;

    _ = posix.write(posix.STDERR_FILENO, "SIGSEGV: Handler entered\n") catch {};

    const fault_addr = getFaultAddress(info);

    var buf: [100]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, "SIGSEGV: Fault at 0x{x}\n", .{fault_addr}) catch "SIGSEGV: Fault address unknown\n";
    _ = posix.write(posix.STDERR_FILENO, msg) catch {};

    // Get current_context from coroutines module
    const current_ctx = coroutines.current_context orelse {
        // Not in a coroutine context - this is a real segfault
        _ = posix.write(posix.STDERR_FILENO, "SIGSEGV: No current context\n") catch {};
        abortOnSegfault(fault_addr);
    };

    _ = posix.write(posix.STDERR_FILENO, "SIGSEGV: Have context\n") catch {};

    const stack_info = &current_ctx.stack_info;

    // Check if allocation_ptr is null (not our stack)
    if (@intFromPtr(stack_info.allocation_ptr) == 0) {
        _ = posix.write(posix.STDERR_FILENO, "SIGSEGV: Null allocation_ptr\n") catch {};
        abortOnSegfault(fault_addr);
    }

    _ = posix.write(posix.STDERR_FILENO, "SIGSEGV: Checking stack region\n") catch {};

    // Check if fault is in uncommitted stack region
    // Stack layout: [guard_page][uncommitted][committed]
    const guard_end = @intFromPtr(stack_info.allocation_ptr) + page_size;
    const uncommitted_start = guard_end;
    const uncommitted_end = stack_info.limit;

    if (fault_addr >= uncommitted_start and fault_addr < uncommitted_end) {
        // Fault is in uncommitted region - extend the stack
        _ = posix.write(posix.STDERR_FILENO, "SIGSEGV: Extending stack\n") catch {};
        stackExtendPosix(stack_info) catch {
            // Extension failed - abort
            _ = posix.write(posix.STDERR_FILENO, "SIGSEGV: Extension failed\n") catch {};
            abortOnStackOverflow(fault_addr);
        };
        // Stack extended successfully - return to resume execution
        _ = posix.write(posix.STDERR_FILENO, "SIGSEGV: Stack extended, returning\n") catch {};
        return;
    }

    // Fault is not in our stack region - this is a real segfault
    _ = posix.write(posix.STDERR_FILENO, "SIGSEGV: Not in stack region\n") catch {};
    abortOnSegfault(fault_addr);
}

/// Abort with diagnostic message on real segmentation fault.
/// Uses async-signal-safe write() to stderr in a single call.
fn abortOnSegfault(fault_addr: usize) noreturn {
    var buf: [100]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, "SIGSEGV: Segmentation fault at address 0x{x}\n", .{fault_addr}) catch "SIGSEGV: Segmentation fault\n";
    _ = posix.write(posix.STDERR_FILENO, msg) catch {};
    posix.abort();
}

/// Abort with diagnostic message on stack overflow.
/// Uses async-signal-safe write() to stderr in a single call.
fn abortOnStackOverflow(fault_addr: usize) noreturn {
    var buf: [100]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, "SIGSEGV: Stack overflow at address 0x{x}\n", .{fault_addr}) catch "SIGSEGV: Stack overflow\n";
    _ = posix.write(posix.STDERR_FILENO, msg) catch {};
    posix.abort();
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

    // Verify at least the requested amount was committed
    // Note: RtlCreateUserStack on Windows may commit more than requested
    const commit_size_rounded = std.mem.alignForward(usize, committed_size, page_size);
    const actual_committed = stack.base - stack.limit;
    try std.testing.expect(actual_committed >= commit_size_rounded);

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
    // Skip on Windows - RtlCreateUserStack handles automatic growth
    if (builtin.os.tag == .windows) return error.SkipZigTest;

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

test "Stack: automatic growth via SIGSEGV" {
    // Skip on Windows - automatic growth works differently
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    std.log.info("TEST: Starting automatic growth test", .{});

    // Setup signal handler for this thread
    std.log.info("TEST: Setting up stack growth", .{});
    try setupStackGrowth();
    defer cleanupStackGrowth();

    std.log.info("TEST: Creating coroutine", .{});
    var parent_context: coroutines.Context = undefined;
    var coro: coroutines.Coroutine = .{
        .parent_context_ptr = &parent_context,
        .context = undefined,
    };

    // Allocate a stack with small initial commit but larger maximum
    const maximum_size = 256 * 1024;
    const initial_commit = 4096; // Very small initial commit
    std.log.info("TEST: Allocating stack (max={d}, commit={d})", .{ maximum_size, initial_commit });
    try stackAlloc(&coro.context.stack_info, maximum_size, initial_commit);
    defer stackFree(coro.context.stack_info);

    const initial_committed = coro.context.stack_info.base - coro.context.stack_info.limit;
    std.log.info("TEST: Initial committed: {d} bytes", .{initial_committed});

    // Recursive function that will exceed initial commit and trigger stack growth
    const RecursiveFn = struct {
        fn recurse(c: *coroutines.Coroutine, depth: u32, target: u32) u32 {
            // Allocate stack space to force growth
            var buffer: [1024]u8 = undefined;
            @memset(&buffer, @intCast(depth & 0xFF));

            if (depth >= target) {
                // Force use of buffer to prevent optimization
                return buffer[0];
            }

            // Recurse deeper
            return recurse(c, depth + 1, target);
        }

        fn start(c: *coroutines.Coroutine, target: u32) u32 {
            return recurse(c, 0, target);
        }
    };

    const Closure = coroutines.Closure(RecursiveFn.start);
    var closure = Closure.init(.{100}); // Recurse 100 times with 1KB per frame = ~100KB

    std.log.info("TEST: Setting up coroutine", .{});
    coro.setup(&Closure.start, &closure);

    // Run coroutine - should trigger automatic stack growth
    std.log.info("TEST: Running coroutine (should trigger stack growth)", .{});
    var step_count: usize = 0;
    while (!coro.finished) {
        step_count += 1;
        std.log.info("TEST: Step {d}", .{step_count});
        coro.step();
    }
    std.log.info("TEST: Coroutine finished after {d} steps", .{step_count});

    // Verify stack grew beyond initial commit
    const final_committed = coro.context.stack_info.base - coro.context.stack_info.limit;
    std.log.info("TEST: Final committed: {d} bytes", .{final_committed});
    std.log.info("TEST: Stack grew by: {d} bytes", .{final_committed - initial_committed});

    try std.testing.expect(final_committed > initial_committed);
    std.log.info("TEST: Complete - stack growth verified", .{});
}
