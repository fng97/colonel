const std = @import("std");

pub fn build(b: *std.Build) void {
    const optimize = b.standardOptimizeOption(.{});
    const target_rv32 = b.resolveTargetQuery(.{
        .cpu_arch = .riscv32,
        .os_tag = .freestanding,
        .abi = .none,
    });

    const kernel_mod = b.createModule(.{
        .root_source_file = b.path("src/kernel.zig"),
        .target = target_rv32,
        .optimize = optimize,
        .strip = false, // keep debug symbols
        .omit_frame_pointer = false, // for stack traces
        .error_tracing = true,
    });
    const kernel_exe = b.addExecutable(.{ .name = "kernel.elf", .root_module = kernel_mod });
    kernel_exe.entry = .disabled;
    kernel_exe.setLinkerScript(b.path("src/kernel.ld"));
    b.installArtifact(kernel_exe);

    // See https://zigtools.org/zls/guides/build-on-save/.
    const check_step = b.step("check", "Check if kernel compiles");
    const check_exe = b.addExecutable(.{ .name = "kernel_check", .root_module = kernel_mod });
    check_step.dependOn(&check_exe.step);

    // User executable to be embedded within the kernel executable. In the absense of a loader in
    // the kernel, the user executable must be converted from ELF to binary to be runnable once
    // embedded.
    const user_exe = b.addExecutable(.{
        .name = "user.elf",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/user.zig"),
            .target = target_rv32,
            .optimize = optimize,
            .strip = false, // TODO: What should this be?
            .omit_frame_pointer = false,
            .error_tracing = true,
        }),
    });
    user_exe.entry = .disabled;
    user_exe.setLinkerScript(b.path("src/user.ld"));
    const elf_to_bin = b.addSystemCommand(&.{
        "llvm-objcopy",
        "--set-section-flags",
        ".bss=alloc,contents",
        "--output-target",
        "binary",
    });
    elf_to_bin.addArtifactArg(user_exe);
    const user_bin = elf_to_bin.addOutputFileArg("user.bin");
    // This allows us to do `@embedFile("user.bin")` in `kernel.zig`.
    kernel_exe.root_module.addAnonymousImport("user.bin", .{ .root_source_file = user_bin });

    const run_step = b.step("run", "Run in QEMU");
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
    const run_cmd = b.addSystemCommand(&qemu_argv);
    run_cmd.addArg("-kernel");
    run_cmd.addArtifactArg(kernel_exe);
    run_step.dependOn(&run_cmd.step);

    const debug_step = b.step("debug", "Run in QEMU, open GDB port, and await connection");
    const debug_cmd = b.addSystemCommand(&qemu_argv);
    debug_cmd.addArgs(&.{ "-S", "-gdb", "tcp::1234" }); // stall CPU and wait for gdb connection
    debug_cmd.addArg("-kernel");
    debug_cmd.addArtifactArg(kernel_exe);
    debug_step.dependOn(&debug_cmd.step);

    const lldb_step = b.step("lldb", "Run LLDB, attach to QEMU");
    const lldb_cmd = b.addSystemCommand(&.{ "lldb", "-o" });
    lldb_cmd.addPrefixedArtifactArg("target create ", kernel_exe);
    lldb_cmd.addArgs(&.{ "-o", "gdb-remote localhost:1234" });
    lldb_step.dependOn(&lldb_cmd.step);

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
    objdump_cmd.addArtifactArg(kernel_exe);
    if (b.args) |args| objdump_cmd.addArgs(args);
    objdump_step.dependOn(&objdump_cmd.step);

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
    symbolizer_cmd.addPrefixedArtifactArg("--obj=", kernel_exe);
    if (b.args) |args| symbolizer_cmd.addArgs(args);
    symbolizer_step.dependOn(&symbolizer_cmd.step);
}
