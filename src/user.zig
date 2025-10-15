const std = @import("std");

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
    while (true) {}
}
