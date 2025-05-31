# Colonel

A toy RISC-V kernel based on the book
[OS in 1,000 Lines](https://operating-system-in-1000-lines.vercel.app). I'm also fortunate to have
[kristos](https://github.com/kristoff-it/kristos) to work from.

Here's a quick peek showing off console prints and the exception handler triggering a kernel panic:

```plaintext
$ zig build run

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

Hello World!
1 + 2 = 3, 1234abcd
PANIC: Unexpected trap scause=2, stval=0, user_pc=80200168
```
