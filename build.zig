const std = @import("std");

pub fn build(b: *std.Build) void {
    const optimize = b.standardOptimizeOption(.{});

    const mod = b.createModule(.{
        .root_source_file = b.path("src/kernel.zig"),
        .target = b.resolveTargetQuery(.{
            .cpu_arch = .riscv32,
            .os_tag = .freestanding,
            .abi = .none,
        }),
        .optimize = optimize,
        .strip = false, // keep debug symbols
        .omit_frame_pointer = false, // for better debuggability
        .error_tracing = true,
    });
    const exe = b.addExecutable(.{ .name = "kernel.elf", .root_module = mod });
    exe.entry = .disabled;
    exe.setLinkerScript(b.path("src/kernel.ld"));

    const inject_debug_info = b.addExecutable(.{
        .name = "inject_debug_info",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/inject_debug_info.zig"),
            .target = b.resolveTargetQuery(.{}), // native
            .optimize = .ReleaseSafe,
        }),
    });
    const inject_debug_info_step = b.addRunArtifact(inject_debug_info);
    // const final_exe = inject_debug_info_step.addPrefixedOutputFileArg("--exe-out", "kernel.elf");
    const final_exe = inject_debug_info_step.addPrefixedOutputFileArg("", "kernel.elf");
    // _ = inject_debug_info_step.addPrefixedArtifactArg("--exe-in", exe);
    _ = inject_debug_info_step.addPrefixedArtifactArg("", exe);
    _ = b.addInstallFile(final_exe, "kernel.elf");

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
    run_cmd.addFileArg(final_exe);
    // Kept doing 'zig build run' and then working with the elf in zig-out without realising it
    // wasn't being updated. Let's make sure it's installed every time.
    run_step.dependOn(b.getInstallStep());
    run_step.dependOn(&run_cmd.step);

    // Easy way to print disassembly with colour. I use it like this:
    // - zig build objdump | less -R  # browse all disassembly (-R -> --raw-control-characters)
    // - zig build objdump -- --disassemble-symbols=kernel_main
    const objdump_step = b.step("objdump", "Show disassembly (accepts args) (pipe me into )");
    const objdump_cmd = b.addSystemCommand(&.{
        "llvm-objdump",
        "--source",
        "--line-numbers",
        "--disassembler-color=on",
        "--no-show-raw-insn",
    });
    objdump_cmd.addFileArg(final_exe);
    if (b.args) |args| objdump_cmd.addArgs(args);
    objdump_step.dependOn(&objdump_cmd.step);

    const debug_step = b.step("debug", "Run in QEMU, open GDB port, and await connection");
    const debug_cmd = b.addSystemCommand(&qemu_argv);
    debug_cmd.addArgs(&.{ "-S", "-gdb", "tcp::1234" }); // stall CPU and wait for gdb connection
    debug_cmd.addArg("-kernel");
    debug_cmd.addFileArg(final_exe);
    debug_step.dependOn(&debug_cmd.step);

    const lldb_step = b.step("lldb", "Run LLDB, attach to QEMU");
    const lldb_cmd = b.addSystemCommand(&.{ "lldb", "-o" });
    lldb_cmd.addPrefixedFileArg("target create ", final_exe);
    lldb_cmd.addArgs(&.{ "-o", "gdb-remote localhost:1234" });
    lldb_step.dependOn(&lldb_cmd.step);

    // Given a sequence of addresses, print the source locations and the code (e.g. to print a stack
    // or error trace).
    const symbolizer_step = b.step("symbolizer", "Resolve symbols from addresses (requires args)");
    const symbolizer_cmd = b.addSystemCommand(&.{
        "llvm-symbolizer",
        "--addresses",
        "--pretty-print",
        "--color=always",
        "--print-source-context-lines=3",
    });
    symbolizer_cmd.addPrefixedFileArg("--obj=", final_exe);
    if (b.args) |args| symbolizer_cmd.addArgs(args);
    symbolizer_step.dependOn(&symbolizer_cmd.step);
}
