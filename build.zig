const std = @import("std");

pub fn build(b: *std.Build) void {
    const mod = b.createModule(.{
        .root_source_file = b.path("src/kernel.zig"),
        .target = b.resolveTargetQuery(.{
            .cpu_arch = .riscv32,
            .os_tag = .freestanding,
            .abi = .none,
        }),
        // Was originally using ReleaseSmall. However, ReleaseSafe makes more sense for development.
        // However, it generates a lot more code. Switch to ReleaseSmall when inspecting assembly.
        .optimize = .ReleaseSafe,
        .strip = false, // keep debug symbols
    });

    const exe = b.addExecutable(.{ .name = "kernel.elf", .root_module = mod });
    exe.entry = .disabled;
    exe.setLinkerScript(b.path("src/kernel.ld"));
    b.installArtifact(exe);

    // See https://zigtools.org/zls/guides/build-on-save/.
    const check = b.step("check", "Check if foo compiles");
    const exe_check = b.addExecutable(.{ .name = "kernel.elf", .root_module = mod });
    exe_check.entry = .disabled;
    exe_check.setLinkerScript(b.path("src/kernel.ld"));
    check.dependOn(&exe_check.step);

    const qemu_argv = .{
        "qemu-system-riscv32",
        "-machine",
        "virt",
        "-bios",
        "default",
        "-serial",
        "mon:stdio",
        "--no-reboot",
        "-nographic",
    };

    const run_step = b.step("run", "Run in QEMU");
    const run_cmd = b.addSystemCommand(&qemu_argv);
    run_cmd.addArg("-kernel");
    run_cmd.addArtifactArg(exe);
    // Kept doing 'zig build run' and then working with the elf in zig-out without realising it
    // wasn't being updated. Let's make sure it's installed every time.
    run_step.dependOn(b.getInstallStep());
    run_step.dependOn(&run_cmd.step);

    const debug_step = b.step("debug", "Run in QEMU, open GDB port, and await connection");
    const debug_cmd = b.addSystemCommand(&qemu_argv);
    debug_cmd.addArgs(&.{ "-gdb", "tcp::1234", "-S" }); // debug args
    debug_cmd.addArg("-kernel");
    debug_cmd.addArtifactArg(exe);
    debug_step.dependOn(b.getInstallStep());
    debug_step.dependOn(&debug_cmd.step);

    const lldb_step = b.step("lldb", "Run LLDB, attach to QEMU");
    const lldb_cmd = b.addSystemCommand(&.{ "lldb", "-o" });
    lldb_cmd.addPrefixedArtifactArg("target create ", exe);
    lldb_cmd.addArgs(&.{ "-o", "gdb-remote localhost:1234" });
    lldb_step.dependOn(&lldb_cmd.step);
}
