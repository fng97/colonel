const std = @import("std");
const syscall = @import("syscall.zig");

const stack_top = @extern([*]u8, .{ .name = "__stack_top" });

/// Entrypoint for user application. The entrypoint should be placed at `.text.start` (start of
/// linker script).
export fn start() linksection(".text.start") callconv(.naked) void {
    asm volatile (
        \\mv sp, %[stack_top]
        \\call %[main]
        :
        : [stack_top] "r" (stack_top),
          [main] "X" (&main),
    );
}

fn main() void {
    const greeting = "Hello from userland, world!";
    for (greeting) |c| syscall.putchar(c);
    while (true) {}
}

// TODO: Where is the stop function?
// TODO: Get stack traces working from userspace.
