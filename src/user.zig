const std = @import("std");
const syscall = @import("syscall.zig");
const common = @import("common.zig");

const console = common.Console{ .putchar = syscall.putchar };

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
    console.print("Hello, from {s}\n", .{"userland"});


    const bad_ptr: *usize = @ptrFromInt(0x80200000);
    console.print("Triggering a page fault by writing to kernel address: {*}\n", .{bad_ptr});
    bad_ptr.* = 0x1234;
}

// TODO: Where is the stop function?
// TODO: Get stack traces working from userspace.
