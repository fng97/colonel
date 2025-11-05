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
