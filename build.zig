const std = @import("std");

pub fn build(b: *std.Build) void {
    const mod = b.createModule(.{
        .root_source_file = b.path("src/kernel.zig"),
        .target = b.resolveTargetQuery(.{
            .cpu_arch = .riscv32,
            .os_tag = .freestanding,
            .abi = .none,
        }),
        .optimize = .ReleaseSmall,
        .strip = false,
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

    const run_step = b.step("run", "Run QEMU");
    const run_cmd = b.addSystemCommand(&.{"qemu-system-riscv32"});
    run_cmd.addArgs(&.{
        "-machine",    "virt",
        "-bios",       "default",
        "-serial",     "mon:stdio",
        "--no-reboot", "-nographic",
        "-kernel",
    });
    run_cmd.addArtifactArg(exe);
    // FIXME: I don't think we need htis
    run_cmd.step.dependOn(b.getInstallStep()); // so we get a zig-out directory on "zig build run"
    run_step.dependOn(&run_cmd.step);
}
