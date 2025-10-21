// TODO: Move this into the kernel source and just expose syscalls with pub for now.

// FIXME: We already have an ecall function. Do we need two?
fn ecall(sysno: usize, arg0: usize, arg1: usize, arg2: usize) usize {
    return asm volatile ("ecall"
        : [ret] "={a0}" (-> usize),
        : [sysno] "{a3}" (sysno),
          [arg0] "{a0}" (arg0),
          [arg1] "{a1}" (arg1),
          [arg2] "{a2}" (arg2),
        : .{ .memory = true });
}

// TODO: This should be an enum.
pub const sys_putchar = 1;

// FIXME: We already have a putchar in the kernel code.
pub fn putchar(char: u8) void {
    _ = ecall(sys_putchar, char, 0, 0);
}
