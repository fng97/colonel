pub const Number = enum(usize) {
    putchar = 1,
    getchar = 2,
    exit = 3,
};

// TODO: Document me and usage of ecall
// FIXME: Is it bad to include all of these args in the assembly even if they're not used?
fn ecall(syscall_number: Number, arg0: usize, arg1: usize, arg2: usize) usize {
    const sn: usize = @intFromEnum(syscall_number);
    return asm volatile ("ecall"
        : [ret] "={a0}" (-> usize),
        : [sn] "{a0}" (sn),
          [arg0] "{a1}" (arg0),
          [arg1] "{a2}" (arg1),
          [arg2] "{a3}" (arg2),
    );
}

pub fn putchar(char: u8) void {
    _ = ecall(.putchar, char, 0, 0);
}

pub fn getchar() u8 {
    return @intCast(ecall(.getchar, 0, 0, 0));
}

pub fn exit() void {
    _ = ecall(.exit, 0, 0, 0);
    @panic("Returned from exit syscall");
}
