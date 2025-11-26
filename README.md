# Colonel

A toy RISC-V kernel based on the book
[OS in 1,000 Lines](https://operating-system-in-1000-lines.vercel.app). I'm also fortunate to have
[kristos](https://github.com/kristoff-it/kristos) to work from.

Here's a quick peek: a userland console showing off context switching, memory virtualisation (Sv32
page tables), and syscalls (console reads and writes). Let's do an illegal access to kernel memory
to make sure the page tables were set up correctly:

```plaintext
fng@Mac ~/s/colonel (main)> zig build run -Doptimize=ReleaseSafe

OpenSBI v1.5.1
   ____                    _____ ____ _____
  / __ \                  / ____|  _ \_   _|
 | |  | |_ __   ___ _ __ | (___ | |_) || |
 | |  | | '_ \ / _ \ '_ \ \___ \|  _ < | |
 | |__| | |_) |  __/ | | |____) | |_) || |_
  \____/| .__/ \___|_| |_|_____/|____/_____|
        | |
        |_|

Platform Name             : riscv-virtio,qemu
...
[kern][inf] Welcome to Colonel
[kern][inf] Creating idle process
[kern][inf] Initialising process 0
[kern][inf] Creating user process: embedded user binary is at u8@8020316c (74288 bytes)
[kern][inf] Initialising process 1
[kern][inf] Context switch: process 0 -> 1

Welcome to userland, this is badshell!
> yo
Invalid command: yo. Try again
> hello
Hello from the shell!!
> segfault
Triggering a fault by writing to kernel address from userland: usize@80200000
[kern][err] PANIC: Unexpected trap scause=f, stval=80200000, user_pc=10005a4
```

Also,
[here](https://github.com/fng97/colonel/blob/2d44d6dd539b702378faa5dfe62aaf3774853221/src/kernel.zig#L173-L203)'s
a simple trick for getting stack traces on freestanding targets. They look like this:

```plaintext
fng@mba ~/s/colonel (main)> zig build run
...
[kern][inf] Welcome to Colonel
[kern][dbg] Clearing BSS
[kern][dbg] Setting trap handler: fn () callconv(.naked) void@8021a654
[kern][inf] Creating idle process
[kern][inf] Initialising process 0
[kern][dbg] Allocated 1 page(s): u8@802e2000 (4096 bytes), 67104768 bytes memory remaining
[kern][dbg] Mapping kernel pages: rwxk
[kern][dbg] Allocated 1 page(s): u8@802e3000 (4096 bytes), 67100672 bytes memory remaining
[kern][dbg] Page directory initialised. Starts at u8@802e3000
[kern][err] PANIC: integer overflow. Inspect stack trace with:

  zig build symbolizer -- 0x8021B7A1 0x8021B43F 0x8021A961 0x8021A58F 0x8021AF0B

QEMU: Terminated
fng@mba ~/s/colonel (main)> zig build symbolizer -- 0x8021B7A1 0x8021B43F 0x8021A961 0x8021A58F 0x8021AF0B
0x8021b7a1: kernel.PageTableEntry.page_table at /Users/fng/src/colonel/src/kernel.zig:703:36
702  :         // const page_number: u32 = pte.ppn;
703 >:         return @ptrFromInt(pte.ppn * page_size_bytes);
704  :     }

0x8021b43f: kernel.map_page at /Users/fng/src/colonel/src/kernel.zig:759:55
758  :     // Map the VPN to the PPN in the page table entry.
759 >:     const page_table = page_directory[vpn1].page_table();
760  :     page_table[vpn0] = .from_address(paddr, flags);

0x8021a961: kernel.create_process at /Users/fng/src/colonel/src/kernel.zig:499:17
498  :     while (paddr < @intFromPtr(&ram_end[0])) : (paddr += page_size_bytes)
499 >:         map_page(page_directory, paddr, paddr, flags);
500  :

0x8021a58f: kernel.main at /Users/fng/src/colonel/src/kernel.zig:81:34
80  :     log.info("Creating idle process\n", .{});
81 >:     process_idle = create_process(undefined);
82  :     process_current = process_idle;

0x8021af0b: kernel_main at /Users/fng/src/colonel/src/kernel.zig:66:9
65  : export fn kernel_main() noreturn {
66 >:     main() catch |err| std.debug.panic("main returned {s}", .{@errorName(err)});
67  :     unreachable;
```
