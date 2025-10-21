pub const Number = enum(usize) { putchar = 1 };

// TODO: Document me and usage of ecall
fn ecall(syscall_number: Number, arg0: usize, arg1: usize, arg2: usize) usize {
    const sn: usize = @intFromEnum(syscall_number);
    return asm volatile ("ecall"
        : [ret] "={a0}" (-> usize),
        : [sysno] "{a3}" (sn),
          [arg0] "{a0}" (arg0),
          [arg1] "{a1}" (arg1),
          [arg2] "{a2}" (arg2),
        : .{ .memory = true });
}

pub fn putchar(char: u8) void {
    _ = ecall(.putchar, char, 0, 0);
}
