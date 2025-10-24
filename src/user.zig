const std = @import("std");
const syscall = @import("syscall.zig");
const common = @import("common.zig");

// TODO: Where is the stop function from the book? Do we need it?
// TODO: Get stack traces working from userspace. Embedding DWARF info would be particularly useful
// here. Symbolizer is more work because `user.elf` doesn't get installed (but I suppose it could)
// so you have to do a clean build with `--verbose` to get the cache path and call llvm-symbolizer
// directly.
// TODO: Add user logging to make output more clear.

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

    console.print("\nWelcome to badshell!\n", .{});
    var buffer: [128]u8 = undefined;
    while (true) {
        console.print("> ", .{});
        var i: usize = 0;
        const line: []const u8 = line: while (i < buffer.len) : (i += 1) {
            const char = syscall.getchar();
            console.print("{c}", .{char});
            if (char == '\r') { // QEMU console newlines use '\r'
                console.print("\n", .{});
                break :line buffer[0..i];
            } else buffer[i] = char;
        } else std.debug.panic("Command too long. Must be less than {d}", .{buffer.len});

        const command = std.meta.stringToEnum(enum { hello, exit }, line) orelse {
            console.print("Invalid command: {s}. Try again\n", .{line});
            continue;
        };

        switch (command) {
            .hello => console.print("Hello from the shell!!\n", .{}),
            .exit => syscall.exit(),
        }
    }

    const bad_ptr: *usize = @ptrFromInt(0x80200000);
    console.print("Triggering a page fault by writing to kernel address: {*}\n", .{bad_ptr});
    bad_ptr.* = 0x1234;
}

pub fn panic(msg: []const u8, _: ?*std.builtin.StackTrace, _: ?usize) noreturn {
    console.print("[user] PANIC: {s}", .{msg});
    while (true) {}
}
