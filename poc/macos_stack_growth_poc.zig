// macOS Stack Growth PoC - Test if SIGSEGV-based stack growth works
//
// Build: zig build-exe macos_stack_growth_poc.zig -target aarch64-macos
//
// This tests whether:
// 1. We can reserve large address space with PROT_NONE
// 2. Commit small initial portion with mprotect
// 3. SIGSEGV handler is called when accessing uncommitted region
// 4. mprotect in signal handler successfully commits more memory

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;

comptime {
    if (!builtin.os.tag.isDarwin()) {
        @compileError("This PoC is for macOS/Darwin only");
    }
}

const STACK_SIZE = 256 * 1024; // 256 KB reserved
const INITIAL_COMMIT = 16 * 1024; // 16 KB initially committed
const PAGE_SIZE = 16 * 1024; // macOS ARM64 uses 16KB pages

// Global state for signal handler
var g_stack_base: usize = 0;
var g_stack_bottom: usize = 0;
var g_current_limit: usize = 0;
var g_faults_handled: usize = 0;

fn sigsegvHandler(_: c_int, info: *const posix.siginfo_t, _: ?*const anyopaque) callconv(.c) void {
    const fault_addr = @intFromPtr(info.addr);

    // Check if fault is in our uncommitted stack region
    if (fault_addr >= g_stack_bottom and fault_addr < g_current_limit) {
        // Commit one page at the fault address
        const page_start = std.mem.alignBackward(usize, fault_addr, PAGE_SIZE);
        const addr: [*]align(PAGE_SIZE) u8 = @ptrFromInt(page_start);

        posix.mprotect(addr[0..PAGE_SIZE], posix.PROT.READ | posix.PROT.WRITE) catch {
            _ = posix.write(posix.STDERR_FILENO, "FATAL: mprotect failed\n") catch {};
            posix.abort();
        };

        g_current_limit = page_start;
        g_faults_handled += 1;
        return;
    }

    // Real segfault
    _ = posix.write(posix.STDERR_FILENO, "FATAL: Real segfault\n") catch {};
    posix.abort();
}

fn recursiveFunc(depth: u32, buffer_ptr: *[1024]u8) u32 {
    // Write to buffer to ensure it's on stack and prevent optimization
    @memset(buffer_ptr, @intCast(depth & 0xFF));

    // Prevent tail call optimization by using the buffer in a meaningful way
    const sum = buffer_ptr[0] +% buffer_ptr[512] +% buffer_ptr[1023];

    if (depth == 0) {
        return sum;
    }

    // Allocate on stack and recurse (volatile to prevent optimization)
    var next_buffer: [1024]u8 = undefined;
    const result = recursiveFunc(depth - 1, &next_buffer);

    // Use both buffers to prevent optimization
    return result +% sum;
}

pub fn main() !void {
    std.debug.print("macOS Stack Growth PoC\n", .{});
    std.debug.print("======================\n\n", .{});

    // Reserve address space with PROT_NONE
    const stack_mem = try posix.mmap(
        null,
        STACK_SIZE,
        posix.PROT.NONE,
        .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
        -1,
        0,
    );
    defer posix.munmap(stack_mem);

    const stack_bottom = @intFromPtr(stack_mem.ptr);
    const stack_top = stack_bottom + STACK_SIZE;

    std.debug.print("Reserved {d} KB at 0x{x}\n", .{ STACK_SIZE / 1024, stack_bottom });

    // Commit initial portion at top
    const initial_start = stack_top - INITIAL_COMMIT;
    const initial_region: [*]align(PAGE_SIZE) u8 = @ptrFromInt(initial_start);
    try posix.mprotect(initial_region[0..INITIAL_COMMIT], posix.PROT.READ | posix.PROT.WRITE);

    std.debug.print("Committed {d} KB at top\n", .{INITIAL_COMMIT / 1024});
    std.debug.print("Uncommitted: {d} KB (PROT_NONE)\n\n", .{(STACK_SIZE - INITIAL_COMMIT) / 1024});

    // Set up signal handler state
    g_stack_base = stack_top;
    g_stack_bottom = stack_bottom;
    g_current_limit = initial_start;

    // Allocate alternate signal stack
    const sigstack_size = 128 * 1024;
    const sigstack = try posix.mmap(
        null,
        sigstack_size,
        posix.PROT.READ | posix.PROT.WRITE,
        .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
        -1,
        0,
    );
    defer posix.munmap(sigstack);

    var ss = posix.stack_t{
        .sp = sigstack.ptr,
        .flags = 0,
        .size = sigstack_size,
    };
    try posix.sigaltstack(&ss, null);

    // Install signal handler for both SIGSEGV and SIGBUS
    // macOS sends SIGBUS for PROT_NONE access, not SIGSEGV
    var sa = posix.Sigaction{
        .handler = .{ .sigaction = sigsegvHandler },
        .mask = posix.sigemptyset(),
        .flags = posix.SA.SIGINFO | posix.SA.ONSTACK,
    };
    posix.sigaction(posix.SIG.SEGV, &sa, null);
    posix.sigaction(posix.SIG.BUS, &sa, null); // macOS uses SIGBUS for PROT_NONE

    std.debug.print("SIGSEGV handler installed\n", .{});
    std.debug.print("Attempting to use {d} KB of stack...\n\n", .{STACK_SIZE / 1024});

    // Test 1: Direct access to uncommitted region
    std.debug.print("Test 1: Writing to uncommitted region (should trigger SIGSEGV)...\n", .{});
    const uncommitted_addr = initial_start - PAGE_SIZE; // One page below committed region
    const uncommitted_ptr: *u8 = @ptrFromInt(uncommitted_addr);
    uncommitted_ptr.* = 42; // This should trigger SIGSEGV and commit the page
    std.debug.print("  ✓ Write succeeded, value: {d}\n", .{uncommitted_ptr.*});
    std.debug.print("  ✓ SIGSEGV faults so far: {d}\n\n", .{g_faults_handled});

    // Test 2: Try to use the stack by recursing
    std.debug.print("Test 2: Recursive function calls...\n", .{});
    var buffer: [1024]u8 = undefined;
    const result = recursiveFunc(200, &buffer);

    std.debug.print("\n✓ All tests passed!\n", .{});
    std.debug.print("Result: {d}\n", .{result});
    std.debug.print("SIGSEGV faults handled: {d}\n", .{g_faults_handled});
    std.debug.print("Final committed: {d} KB\n", .{(stack_top - g_current_limit) / 1024});
}
