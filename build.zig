const std = @import("std");

pub fn build(b: *std.Build) void {
    const exe = b.addExecutable(.{
        .name = "kernel.elf",
        .root_source_file = b.path("src/kernel.zig"),
        .target = b.resolveTargetQuery(.{
            .cpu_arch = .riscv32,
            .os_tag = .freestanding,
            .abi = .none,
        }),
        .optimize = .ReleaseSmall,
        .strip = false,
    });
    exe.entry = .disabled;
    exe.setLinkerScript(b.path("src/kernel.ld"));
    b.installArtifact(exe);

    // See https://zigtools.org/zls/guides/build-on-save/.
    const exe_check = b.addExecutable(.{
        .name = "kernel.elf",
        .root_source_file = b.path("src/kernel.zig"),
        .target = b.resolveTargetQuery(.{
            .cpu_arch = .riscv32,
            .os_tag = .freestanding,
            .abi = .none,
        }),
        .optimize = .ReleaseSmall,
        .strip = false,
    });
    exe_check.entry = .disabled;
    exe_check.setLinkerScript(b.path("src/kernel.ld"));
    const check = b.step("check", "Check if foo compiles");
    check.dependOn(&exe_check.step);

    const run_cmd = b.addSystemCommand(&.{
        "qemu-system-riscv32",
    });
    run_cmd.addArgs(&.{
        "-machine",    "virt",
        "-bios",       "default",
        "-serial",     "mon:stdio",
        "--no-reboot", "-nographic",
        "-kernel",
    });
    run_cmd.addArtifactArg(exe);
    run_cmd.step.dependOn(b.getInstallStep()); // so we get a zig-out directory on "zig build run"
    const run_step = b.step("run", "Run QEMU");
    run_step.dependOn(&run_cmd.step);
}
