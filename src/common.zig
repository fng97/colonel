const std = @import("std");

pub const Console = struct {
    interface: std.Io.Writer = .{ .vtable = &.{ .drain = drain }, .buffer = &.{} },
    putchar: *const fn (u8) void,

    /// Infallible console.writer().print() wrapper.
    pub fn print(console: *const Console, comptime fmt: []const u8, args: anytype) void {
        console.writer().print(fmt, args) catch unreachable;
    }

    fn writer(console: *const Console) *std.Io.Writer {
        return @constCast(&console.interface);
    }

    fn drain(w: *std.io.Writer, data: []const []const u8, _: usize) !usize {
        const console: *const Console = @fieldParentPtr("interface", w);
        var len: usize = 0;
        for (data) |slice| {
            for (slice) |c| console.putchar(c);
            len += slice.len;
        }
        return len;
    }
};
