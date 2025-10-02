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

    const run_step = b.step("run", "Run with QEMU");
    const run_cmd = b.addSystemCommand(&.{
        "qemu-system-riscv32",
        "-machine",
        "virt",
        "-bios",
        "default",
        "-serial",
        "mon:stdio",
        "--no-reboot",
        "-nographic",
        "-kernel",
    });
    run_cmd.addArtifactArg(exe);
    // Kept doing 'zig build run' and then working with the elf in zig-out without realising it
    // wasn't being updated. Let's make sure it's installed every time.
    run_cmd.step.dependOn(b.getInstallStep());
    run_step.dependOn(&run_cmd.step);

    const debug_step = b.step("debug", "Debug with QEMU and LLDB");
    // FIXME: Using bash to manage the two processes for now. I'm sure there's a better way. Maybe
    // we should create two separate steps, one for starting QEMU in debug mode and another for
    // connecting LLDB. That way, we could work from both in separate shells.
    const debug_cmd = b.addSystemCommand(&.{
        "bash", "-c",
        \\set -euxo pipefail
        \\
        // Same command as above (except we specify "kernel.elf" path) until the next comment.
        \\qemu-system-riscv32 \
        \\      -machine virt \
        \\      -bios default \
        \\      -serial mon:stdio \
        \\      --no-reboot \
        \\      -nographic \
        \\      -kernel zig-out/bin/kernel.elf \
        // Listen for debug connection.
        \\      -gdb tcp::1234 \
        // Stall CPU at startup so that it is started by the debugger.
        \\      -S \
        // Background QEMU and start LLDB.
        \\      & lldb -o "target create zig-out/bin/kernel.elf" \
        \\           -o "gdb-remote localhost:1234"
    });
    debug_cmd.step.dependOn(b.getInstallStep());
    debug_step.dependOn(&debug_cmd.step);
}
