Low-level library for implementing stackful coroutines for Zig.

Tested on Linux, FreeBSD, NetBSD, macOS and Windows.

Features:
 - context switching on x86_64/aarch64/riscv64 architectures via custom assembly
 - allocating stacks on virtual memory with proper stack guard pages
 - growable stacks within the reserved virtual memory space
    * automatic on Windows
    * custom SIGSEGV signal handler on POSIX (opt-in)
 - stacks registered with Valgrind in debug mode
 

