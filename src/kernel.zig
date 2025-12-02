/// RISC-V toy kernel based on the book 'OS in 1,000 Lines'

// From The RISC-V Instruction Set Manual, Volume I: User-Level ISA, Chapter 18: Calling Convention)
//
// +----------+-----------+---------------------------------+---------+
// | Register | ABI Name  | Description                     | Saver   |
// +----------+-----------+---------------------------------+---------+
// | x0       | zero      | Hard-wired zero                 | —       |
// | x1       | ra        | Return address                  | Caller  |
// | x2       | sp        | Stack pointer                   | Callee  |
// | x3       | gp        | Global pointer                  | —       |
// | x4       | tp        | Thread pointer                  | —       |
// | x5–7     | t0–2      | Temporaries                     | Caller  |
// | x8       | s0/fp     | Saved register/frame pointer    | Callee  |
// | x9       | s1        | Saved register                  | Callee  |
// | x10–11   | a0–1      | Function arguments/return values| Caller  |
// | x12–17   | a2–7      | Function arguments              | Caller  |
// | x18–27   | s2–11     | Saved registers                 | Callee  |
// | x28–31   | t3–6      | Temporaries                     | Caller  |
// +----------+-----------+---------------------------------+---------+
// | f0–7     | ft0–7     | FP temporaries                  | Caller  |
// | f8–9     | fs0–1     | FP saved registers              | Callee  |
// | f10–11   | fa0–1     | FP arguments/return values      | Caller  |
// | f12–17   | fa2–7     | FP arguments                    | Caller  |
// | f18–27   | fs2–11    | FP saved registers              | Callee  |
// | f28–31   | ft8–11    | FP temporaries                  | Caller  |
// +----------+-----------+---------------------------------+---------+
//
// Table 18.2: RISC-V calling convention register usage.

// TODO:
// - Stack traces broke again.
// - Get assertions working.
// - Add stack overflow protection.
// - Print program size on build.

const std = @import("std");
const syscall = @import("syscall.zig");
const common = @import("common.zig");

/// Embedded user binary built from `user.zig`.
const user_bin = @embedFile("user.bin");

// Symbols from the linker script.
const kernel_base = @extern([*]u8, .{ .name = "__kernel_base" }); // start of kernel memory
const bss = @extern([*]u8, .{ .name = "__bss" });
const bss_end = @extern([*]u8, .{ .name = "__bss_end" });
const stack_top = @extern([*]u8, .{ .name = "__stack_top" });
const ram_start = @extern([*]u8, .{ .name = "__free_ram" });
const ram_end = @extern([*]u8, .{ .name = "__free_ram_end" }); // end of kernel memory

/// This is the entrypoint of the program as defined in the linker script.
export fn boot() linksection(".text.boot") callconv(.naked) void {
    asm volatile (
        \\mv sp, %[stack_top]
        \\j kernel_main
        :
        : [stack_top] "r" (stack_top),
    );
}

/// The kernel main function called by boot. This just calls main. Because boot uses inline assembly
/// to jump here and the ABI doesn't know how to handle returned Zig's errors we just use this
/// function to bridge the gap. We catch and print any errors here so that we can use try in main.
export fn kernel_main() noreturn {
    main() catch |err| std.debug.panic("main returned {s}", .{@errorName(err)});
    unreachable;
}

fn main() !void {
    log.info("Welcome to Colonel\n", .{});

    // Ensure the bss section is cleared to zero.
    log.debug("Clearing BSS\n", .{});
    @memset(bss[0 .. bss_end - bss], 0);

    log.debug("Setting trap handler: {*}\n", .{&kernel_entry});
    write_csr("stvec", @intFromPtr(&kernel_entry));

    virtio_blk_init();
    var buf: [sector_size]u8 = undefined;
    read_write_disk(&buf, 0, false);
    log.info("first sector: {s}\n", .{buf});
    @memcpy(buf[0..21], "hello from kernel!!!\n");
    read_write_disk(&buf, 0, true);

    log.info("Creating idle process\n", .{});
    process_idle = create_process(undefined);
    process_current = process_idle;

    log.info(
        "Creating user process: embedded user binary is at {*} ({d} bytes)\n",
        .{ user_bin.ptr, user_bin.len },
    );
    _ = create_process(user_bin);

    yield();

    @panic("Switched to idle process");
}

// SUPERVISOR BINARY INTERFACE (SBI) CALLS

const Sbi = struct {
    const Result = struct {
        err: isize,
        value: isize,
    };

    /// Perform an Environment Call (ECAll) using the Supervisor Binary Interface (SBI). This is
    /// used to implement a syscall: a call from user mode to execute higher privileged code.
    fn ecall(
        arg0: usize,
        arg1: usize,
        arg2: usize,
        arg3: usize,
        arg4: usize,
        arg5: usize,
        fid: usize,
        eid: usize,
    ) Result {
        var err: isize = undefined;
        var value: isize = undefined;

        asm volatile ("ecall"
            : [err] "={a0}" (err),
              [value] "={a1}" (value),
            : [arg0] "{a0}" (arg0),
              [arg1] "{a1}" (arg1),
              [arg2] "{a2}" (arg2),
              [arg3] "{a3}" (arg3),
              [arg4] "{a4}" (arg4),
              [arg5] "{a5}" (arg5),
              [arg6] "{a6}" (fid),
              [arg7] "{a7}" (eid),
            : .{ .memory = true });

        return .{ .err = err, .value = value };
    }

    pub fn putchar(char: u8) void {
        _ = ecall(char, 0, 0, 0, 0, 0, 0, 1);
    }

    pub fn getchar() u8 {
        const ret = ecall(0, 0, 0, 0, 0, 0, 0, 2);
        switch (ret.err) {
            0...255 => |char| return @intCast(char),
            -1 => @panic("getchar ecall failed"),
            else => @panic("getchar ecall returned non-ascii value"),
        }
    }
};

// SERIAL CONSOLE

const console = common.Console{ .putchar = Sbi.putchar };

const log = std.log.scoped(.kern);
pub const std_options: std.Options = .{
    // .log_level = .debug,
    .logFn = struct {
        pub fn log(
            comptime level: std.log.Level,
            comptime scope: @TypeOf(.EnumLiteral),
            comptime format: []const u8,
            args: anytype,
        ) void {
            console.print("[{s}][{s}] ", .{ @tagName(scope), switch (level) {
                .err => "err",
                .info => "inf",
                .warn => "wrn",
                .debug => "dbg",
            } });
            console.print(format, args);
        }
    }.log,
};

pub const panic = std.debug.FullPanic(struct {
    /// Global panic handler. This prints the panic message, generates a command to print a
    /// stack/error trace, then hangs. Printing a stack trace on freestanding is not trivial. See:
    /// https://andrewkelley.me/post/zig-stack-traces-kernel-panic-bare-bones-os.html. Instead, we
    /// let llvm-symbolizer do all the heavy lifting: given the list of addresses in our stack trace
    /// it prints one for us. Using a zig build entrypoint ensures llvm-symbolizer is passed our
    /// executable. The panic handler prints the list of addresses so that it's a one liner for the
    /// user to copy:
    /// zig build symbolizer -- {space-delimited-addresses}
    fn panic_handler(msg: []const u8, return_address: ?usize) noreturn {
        log.err("PANIC: {s}. Inspect stack trace with:\n\n  zig build symbolizer --", .{msg});

        // TODO: Disable interrupts?
        // TODO: Detect double panics?

        if (@errorReturnTrace()) |trace| {
            const trace_index = @min(trace.index, trace.instruction_addresses.len);
            for (0..trace_index) |i| console.print(
                " 0x{X:0>8}",
                .{trace.instruction_addresses[i] - 1},
            );
        }

        var iter = std.debug.StackIterator.init(return_address orelse @returnAddress(), null);
        while (iter.next()) |address| console.print(" 0x{X:0>8}", .{address - 1});

        console.print("\n\n", .{}); // make some room so it's easy to copy the one-liner

        while (true) asm volatile ("");
    }
}.panic_handler);

// TRAP HANDLER

const TrapFrame = struct {
    ra: usize,
    gp: usize,
    tp: usize,
    t0: usize,
    t1: usize,
    t2: usize,
    t3: usize,
    t4: usize,
    t5: usize,
    t6: usize,
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
    a7: usize,
    s0: usize,
    s1: usize,
    s2: usize,
    s3: usize,
    s4: usize,
    s5: usize,
    s6: usize,
    s7: usize,
    s8: usize,
    s9: usize,
    s10: usize,
    s11: usize,
    sp: usize,
};

/// Preserves the CPU state by saving all general-purpose registers.
///
/// RISC-V defines 32 integer registers. The first integer register is a zero register, and the
/// remainder are general-purpose registers. The kernel allocates extra stack space to store the
/// general purpose registers in the format described by the TrapFrame structure. `handle_trap` is
/// passed a pointer to this structure and handles the exception logic. The CPU state is then
/// restored and execution is resumed.
export fn kernel_entry() align(4) callconv(.naked) void {
    asm volatile (
    // Swap the current user/pre-trap stack pointer with the kernel stack pointer previously stored
    // in yield().
        \\csrrw sp, sscratch, sp

        // Decrease the stack pointer to allocate space for the 31 general purpose registers (4
        // bytes each). The resulting address in sp will be passed to handle_trap and cast to
        // TrapFrame.
        \\addi sp, sp, -4 * 31

        // Store the remaining 30 general purpose registers (we'll store the original stack pointer
        // further down). After this block the state is captured and the kernel can begin using
        // these registers.
        \\sw ra,  4 * 0(sp)
        \\sw gp,  4 * 1(sp)
        \\sw tp,  4 * 2(sp)
        \\sw t0,  4 * 3(sp)
        \\sw t1,  4 * 4(sp)
        \\sw t2,  4 * 5(sp)
        \\sw t3,  4 * 6(sp)
        \\sw t4,  4 * 7(sp)
        \\sw t5,  4 * 8(sp)
        \\sw t6,  4 * 9(sp)
        \\sw a0,  4 * 10(sp)
        \\sw a1,  4 * 11(sp)
        \\sw a2,  4 * 12(sp)
        \\sw a3,  4 * 13(sp)
        \\sw a4,  4 * 14(sp)
        \\sw a5,  4 * 15(sp)
        \\sw a6,  4 * 16(sp)
        \\sw a7,  4 * 17(sp)
        \\sw s0,  4 * 18(sp)
        \\sw s1,  4 * 19(sp)
        \\sw s2,  4 * 20(sp)
        \\sw s3,  4 * 21(sp)
        \\sw s4,  4 * 22(sp)
        \\sw s5,  4 * 23(sp)
        \\sw s6,  4 * 24(sp)
        \\sw s7,  4 * 25(sp)
        \\sw s8,  4 * 26(sp)
        \\sw s9,  4 * 27(sp)
        \\sw s10, 4 * 28(sp)
        \\sw s11, 4 * 29(sp)

        // Store the original sp (at time of the exception) at the end of the space we allocated
        // (you can see it's the last item in TrapFrame).
        \\csrr a0, sscratch
        \\sw a0, 4 * 30(sp)

        // Restore the original kernel stack pointer to sscratch. sscratch must hold a usable kernel
        // stack pointer (instead of user sp) in case we have a nested trap or interrupt.
        \\addi a0, sp, 4 * 31
        \\csrw sscratch, a0

        // Call handle_trap with a pointer to the start of TrapFrame.
        \\mv a0, sp
        \\call handle_trap

        // Restore the general purpose registers and resume execution.
        \\lw ra,  4 * 0(sp)
        \\lw gp,  4 * 1(sp)
        \\lw tp,  4 * 2(sp)
        \\lw t0,  4 * 3(sp)
        \\lw t1,  4 * 4(sp)
        \\lw t2,  4 * 5(sp)
        \\lw t3,  4 * 6(sp)
        \\lw t4,  4 * 7(sp)
        \\lw t5,  4 * 8(sp)
        \\lw t6,  4 * 9(sp)
        \\lw a0,  4 * 10(sp)
        \\lw a1,  4 * 11(sp)
        \\lw a2,  4 * 12(sp)
        \\lw a3,  4 * 13(sp)
        \\lw a4,  4 * 14(sp)
        \\lw a5,  4 * 15(sp)
        \\lw a6,  4 * 16(sp)
        \\lw a7,  4 * 17(sp)
        \\lw s0,  4 * 18(sp)
        \\lw s1,  4 * 19(sp)
        \\lw s2,  4 * 20(sp)
        \\lw s3,  4 * 21(sp)
        \\lw s4,  4 * 22(sp)
        \\lw s5,  4 * 23(sp)
        \\lw s6,  4 * 24(sp)
        \\lw s7,  4 * 25(sp)
        \\lw s8,  4 * 26(sp)
        \\lw s9,  4 * 27(sp)
        \\lw s10, 4 * 28(sp)
        \\lw s11, 4 * 29(sp)
        \\lw sp,  4 * 30(sp)
        \\sret
    );
}

// TODO: This should be an enum.
const scause_ecall = 8;

export fn handle_trap(trap_frame: *TrapFrame) void {
    const scause = read_csr("scause");
    const stval = read_csr("stval");
    const user_pc = read_csr("sepc");

    // Handle syscalls.
    if (scause == scause_ecall) {
        // Besides calling the handle_syscall function, we also add 4 (the size of ecall
        // instruction) to the value of sepc. This is because sepc points to the program counter
        // that caused the exception, which points to the ecall instruction. If we don't change it,
        // the kernel goes back to the same place, and the ecall instruction is executed repeatedly.
        write_csr("sepc", user_pc + 4);

        // The syscall number is passed by argument in a0.
        const syscall_number = std.meta.intToEnum(syscall.Number, trap_frame.a0) catch
            std.debug.panic("Invalid syscall: {x}", .{trap_frame.a0});
        switch (syscall_number) {
            .putchar => Sbi.putchar(@intCast(trap_frame.a1)),
            .getchar => getchar: while (true) {
                const ret = Sbi.ecall(0, 0, 0, 0, 0, 0, 0, 2);
                if (ret.err >= 0) {
                    trap_frame.a0 = @intCast(ret.err); // return via a0
                    break :getchar;
                } else yield(); // so that IO doesn't block everything
            },
            // TODO: Free process resources on exit.
            .exit => {
                log.info("process {d} exited\n", .{process_current.pid});
                process_current.state = .exited;
                yield();
                unreachable;
            },
        }
    } else std.debug.panic(
        "Unexpected trap scause={x}, stval={x}, user_pc={x}",
        .{ scause, stval, user_pc },
    );
}

/// Read control and status register (CSR).
fn read_csr(comptime register: []const u8) usize {
    return asm volatile ("csrr %[ret], " ++ register
        : [ret] "=r" (-> usize),
    );
}

/// Write control and status register (CSR).
fn write_csr(comptime register: []const u8, val: usize) void {
    asm volatile ("csrw " ++ register ++ ", %[val]"
        :
        : [val] "r" (val),
    );
}

// MEMORY ALLOCATION

var ram_used_bytes: usize = 0;
const page_size_bytes = 4096;

/// A simple bump allocator. Clears allocated memory to zero.
///
/// TODO: Support freeing memory. Consider a bitmap-based algorithm or the "buddy system".
fn alloc_pages(pages: usize) []u8 {
    const ram: []u8 = ram_start[0 .. ram_end - ram_start];

    const alloc_size_bytes = pages * page_size_bytes;
    const ram_available = ram[ram_used_bytes..];

    if (alloc_size_bytes > ram_available.len) @panic("Out of memory");

    const result = ram_available[0..alloc_size_bytes];
    @memset(result, 0);
    ram_used_bytes += alloc_size_bytes;

    log.debug(
        "Allocated {d} page(s): {*} ({} bytes), {} bytes memory remaining\n",
        .{ pages, result.ptr, result.len, ram_available.len - alloc_size_bytes },
    );

    return result;
}

// PROCESSES

const Process = struct {
    /// The conventional name for the process ID.
    pid: u32,
    state: enum { unused, runnable, exited },
    /// The conventional name for the stack pointer.
    sp: usize,
    /// Pointer to the first-level page table, the page directory.
    page_directory: *[page_table_size]PageTableEntry,
    /// Used to store CPU registers, return addresses (where it was called from), and local
    /// variables between context switches.
    stack: [8192]u8 align(4),
};

var processes = [_]Process{.{
    .pid = 0,
    .state = .unused,
    .sp = undefined,
    .page_directory = undefined,
    .stack = undefined,
}} ** 8;

var process_current: *Process = undefined;
var process_idle: *Process = undefined;

/// Create a process, reserving space in its stack for callee-saved registers, and setting the
/// entrypoint (pc argument). Refer to the chart at the top of this file for what registers must be
/// saved.
///
/// NOTE: The first process created must be the idle process (pid == 0) for yield() to work.
fn create_process(image: []const u8) *Process {
    const process = for (&processes, 0..) |*process, pid| {
        if (process.state == .unused) {
            process.pid = pid;
            break process;
        }
    } else @panic("No free process slots");
    log.info("Initialising process {d}\n", .{process.pid});

    // Reserve space for the callee-saved registers on the stack. s0-s11 are zero-initialised and ra
    // is set to the process entrypoint. These will be restored in the first context switch. sp is
    // stored in the Process struct and points to the bottom of stack (which will hold ra).
    const registers = blk: {
        // Get the stack as a []usize from []u8 because we're working with registers.
        const ptr: [*]usize = @ptrCast(@alignCast(&process.stack));
        const stack = ptr[0 .. process.stack.len / @sizeOf(usize)];

        const registers = stack[stack.len - 13 ..]; // 14 callee-saved registers (-1 for sp)
        for (registers[1..]) |*register| register.* = 0; // s0-s11
        registers[0] = @intFromPtr(&user_entry); // ra

        break :blk registers;
    };

    // Initialise a page directory for the process.
    const page_directory_buffer = alloc_pages(1);
    const page_directory: *[page_table_size]PageTableEntry =
        @ptrCast(@alignCast(page_directory_buffer.ptr));

    // Map kernel pages: from the start of memory (kernel_base) to the end (ram_end). Kernel virtual
    // addresses are mapped to physical addresses for simplicity.
    var paddr: usize = @intFromPtr(&kernel_base[0]);
    const flags = PageTableEntry.Flags{
        .readable = true,
        .writable = true,
        .executable = true,
        .user = false,
    };
    log.debug("Mapping kernel pages: {f}\n", .{flags});
    while (paddr < @intFromPtr(&ram_end[0])) : (paddr += page_size_bytes)
        map_page(page_directory, paddr, paddr, flags);

    // Map virtio-blk MMIO region.
    map_page(page_directory, virtio_blk_paddr, virtio_blk_paddr, .{
        .readable = true,
        .writable = true,
        .executable = false,
        .user = false,
    });

    // Map user pages.
    var pos: usize = 0;
    while (pos < image.len) : (pos += page_size_bytes) {
        const page = alloc_pages(1);

        // Handle the case where the data to be copied is smaller than the page size.
        const remaining = image.len - pos;
        // TODO: @min()
        const copy_size = if (page_size_bytes <= remaining) page_size_bytes else remaining;

        // Fill and map the page.
        @memcpy(page[0..copy_size], image[pos .. pos + copy_size]);
        map_page(page_directory, user_base + pos, @intFromPtr(page.ptr), .{
            .readable = true,
            .writable = true,
            .executable = true,
            .user = true,
        });
    }

    process.sp = @intFromPtr(registers.ptr);
    process.page_directory = page_directory;
    process.state = .runnable;
    return process;
}

/// Search for a runnable process, starting with the next process (pid + 1) and ending with the
/// current process. This is the "round robin" scheduling approach. If no processes are runnable
/// switch to the idle process.
fn yield() void {
    // Process.pid is also the index of the process so we can loop through pid offsets (wrapping
    // around with % process.len) until we've checked all the processes including the current
    // process.
    const process_next = for (1..processes.len + 1) |i| {
        const process = &processes[(process_current.pid + i) % processes.len];
        if (process.state == .runnable and process.pid > 0) break process;
    } else process_idle;

    if (process_next == process_current) return;

    log.info(
        "Context switch: process {d} -> {d}\n",
        .{ process_current.pid, process_next.pid },
    );

    asm volatile (
        \\sfence.vma
        // Update the SATP CSR with the next process's page table.
        \\csrw satp, %[satp]
        \\sfence.vma
        \\csrw sscratch, %[sscratch]
        :
        : [satp] "r" (SatpCsr.from_page_directory(process_next.page_directory)),
          [sscratch] "r" (@intFromPtr(process_next.stack[0..].ptr) + process_next.stack.len),
    );

    const previous = process_current;
    process_current = process_next;
    switch_context(&previous.sp, &process_next.sp);
}

/// Context switch: save the current process's callee-saved registers (s0-s11 and ra) to its stack,
/// swap the stack pointers, then restore the next process's callee-saved registers from its stack.
/// This function is naked because it contains a ret instruction that returns to a different
/// location than where it was called from, which would be undefined behaviour in a normal function.
fn switch_context_naked() callconv(.naked) void {
    asm volatile (
    // Allocate space for 13 4-byte registers.
        \\addi sp, sp, -13 * 4

        // Save current process's registers.
        \\sw ra,  0  * 4(sp)
        \\sw s0,  1  * 4(sp)
        \\sw s1,  2  * 4(sp)
        \\sw s2,  3  * 4(sp)
        \\sw s3,  4  * 4(sp)
        \\sw s4,  5  * 4(sp)
        \\sw s5,  6  * 4(sp)
        \\sw s6,  7  * 4(sp)
        \\sw s7,  8  * 4(sp)
        \\sw s8,  9  * 4(sp)
        \\sw s9,  10 * 4(sp)
        \\sw s10, 11 * 4(sp)
        \\sw s11, 12 * 4(sp)

        // Switch the stack pointer. See arguments passed to switch_context.
        \\sw sp, (a0) // *sp_addr_prev = sp
        \\lw sp, (a1) // sp = *sp_addr_next

        // Restore next process's registers from its stack.
        \\lw ra,  0  * 4(sp)
        \\lw s0,  1  * 4(sp)
        \\lw s1,  2  * 4(sp)
        \\lw s2,  3  * 4(sp)
        \\lw s3,  4  * 4(sp)
        \\lw s4,  5  * 4(sp)
        \\lw s5,  6  * 4(sp)
        \\lw s6,  7  * 4(sp)
        \\lw s7,  8  * 4(sp)
        \\lw s8,  9  * 4(sp)
        \\lw s9,  10 * 4(sp)
        \\lw s10, 11 * 4(sp)
        \\lw s11, 12 * 4(sp)

        // After popping the 13 4-byte registers from the next process's stack we can restore the
        // stack pointer to where it was before yielding execution and return.
        \\addi sp, sp, 13 * 4
        \\ret
    );
}

/// Cast switch_context_naked to the right calling convention.
const switch_context = @as(*const fn (*usize, *usize) callconv(.c) void, @ptrCast(&switch_context_naked));

// PAGE TABLE

// NOTE: We're using Sv32 which (I think) stands for [S]upervisor-mode [V]irtual memory with 32-bit
// virtual addresses. It uses a two-level page table. The 32-bit virtual address is divided into a
// first-level page table index (VPN[1]), a second-level page table index (VPN[0]), and a page
// offset. That's right, they call the first-level page table table1 and the second-level page table
// table0... I think it's because to get a physical address from a virtual address you index the
// first-level page table before the second-level page table.

/// Virtual addresses are mapped to physical addresses by the kernel. Their 32-bit structure stores
/// two virtual page numbers (VPN[1] and VPN[0]) and an offset used by the CPU to look up the
/// physical addresses using the page tables:
///
/// 1. The CPU is given the address of the process's page directory by the kernel (see SATP CSR).
/// 2. The entry at index VPN[1] in the page directory stores the physical page number (PPN)
///    of the page table.
/// 3. The entry at index VPN[0] in the page table stores PPN of the physical page containing the
///    physical address.
/// 4. Finally, the offset indicates the physical address in that page.
const VirtualAddress = packed struct(u32) {
    /// The page offset indexes bytes in a page (it's 12 bits because a page is 2^12 = 4096 bytes).
    offset: u12,
    /// Index into the second-level page table (table0). This index is referred to as VPN[2]: the
    /// [V]irtual [P]age [N]umber of the [2]nd-level page table.
    vpn0: u10,
    /// Index into the first-level page table (the page directory, table1). This index is referred
    /// to as VPN[1]: the [V]irtual [P]age [N]umber of the [1]st-level page table.
    vpn1: u10,
};

/// The number of entries in a (first or second level) page table. This are 1024 entries on a 32-bit
/// system with a page size of 4 KiB.
const page_table_size = page_size_bytes / @sizeOf(PageTableEntry);

/// A page table entry stores a physical page number which corresponds to the physical address of a
/// page. Sv32 uses two levels of page tables. A valid entry in the first-level page table (referred
/// to as the page directory) points to a second-level page table (referred to as the page table). A
/// valid entry in the second-level page table points to a mapped page.
///
/// Page table structures are used to map virtual addresses to physical addresses. These physical
/// addresses are always aligned to (read: multiples of) the page size (4096 bytes). If we stored
/// these as 32-bit addresses, the 12 least significant bits would be zero (2^12 = 4096). By storing
/// them as multiples of the page size (page numbers) we free up those 12 bits! This allows us to
/// use 10 of the 32 bits for flags and the remaining 22 bits for the page number. That means we
/// actually have 34-bit addresses: 22 bits plus the 12-bit offset. Therefore, Rv32 allows us to map
/// a 32-bit virtual address space (4 GiB) to a 34-bit physical address space (16 GiB). In other
/// words, a process can use up to 4 GiB of virtual memory but the CPU can access up to 16 GiB of
/// physical memory.
const PageTableEntry = packed struct(u32) {
    valid: bool, // entry is initialised
    flags: Flags,
    /// Physical page number (PPN).
    ppn: u22,

    const Flags = packed struct(u9) {
        readable: bool,
        writable: bool,
        executable: bool,
        user: bool, // accessible in user mode
        _: u5 = 0, // no idea what these do

        pub fn format(flags: Flags, writer: *std.Io.Writer) !void {
            try writer.print(
                "{c}{c}{c}{c}",
                .{
                    @as(u8, if (flags.readable) 'r' else '-'),
                    @as(u8, if (flags.writable) 'w' else '-'),
                    @as(u8, if (flags.executable) 'x' else '-'),
                    @as(u8, if (flags.user) 'u' else 'k'),
                },
            );
        }
    };

    /// Create a valid page table entry from an address with the provided flags.
    fn from_address(addr: u32, flags: Flags) PageTableEntry {
        return .{
            .valid = true,
            .flags = flags,
            .ppn = @intCast(addr / page_size_bytes),
        };
    }

    /// Get a pointer to the page table that lives at the stored address. This method is only used
    /// on page directory entries.
    fn page_table(pte: PageTableEntry) *[page_table_size]PageTableEntry {
        // The page number must be widened from u22 to u32 to prevent overflow.
        const page_number: u32 = pte.ppn;
        return @ptrFromInt(page_number * page_size_bytes);
    }
};

/// Register structure that enables Sv32 paging in the Supervisor Address Translation and Protection
/// (SATP) CSR. This CSR updated every time we context switch with the next context's page directory
/// so that the CPU is looking up virtual addresses using the correct page tables.
const SatpCsr = packed struct(u32) {
    page_number: u31,
    enable_sv32: bool,

    fn from_page_directory(page_directory: *[page_table_size]PageTableEntry) u32 {
        const page_number: u32 = @intFromPtr(page_directory.ptr) / page_size_bytes;
        return @bitCast(SatpCsr{
            .page_number = @intCast(page_number),
            .enable_sv32 = true,
        });
    }
};

/// Map a virtual address to a physical address.
///
/// There are 1024 entries in a page directory, a.k.a. the first-level page table. That is, it is
/// one page in size (4096 bytes): 1024 32-bit entries. Each entry points to a (second-level) page
/// table that also contains 1024 entries (another 4096 bytes). Each of those entries hold the
/// physical address of a page.
fn map_page(
    page_directory: *[page_table_size]PageTableEntry,
    vaddr: u32,
    paddr: u32,
    flags: PageTableEntry.Flags,
) void {
    if (vaddr % page_size_bytes != 0) std.debug.panic("unaligned vaddr ({})", .{vaddr});
    if (paddr % page_size_bytes != 0) std.debug.panic("unaligned paddr ({})", .{paddr});

    const virtual_address: VirtualAddress = @bitCast(vaddr);
    const vpn0 = virtual_address.vpn0;
    const vpn1 = virtual_address.vpn1;

    // Ensure the page directory entry has been initialised: the page table it points to has been
    // allocated. Page tables are one page in size. Allocated pages are already cleared to zero.
    if (!page_directory[vpn1].valid) {
        const addr = alloc_pages(1).ptr;
        page_directory[vpn1] = .from_address(
            @intFromPtr(addr),
            .{
                .readable = false,
                .writable = false,
                .executable = false,
                .user = false,
            },
        );
        log.debug("Page directory initialised. Starts at {*}\n", .{addr});
    }

    // Map the VPN to the PPN in the page table entry.
    const page_table = page_directory[vpn1].page_table();
    page_table[vpn0] = .from_address(paddr, flags);
}

// USER MODE

/// The base virtual address of an application image. This needs to match the starting address
/// defined in `user.ld`.
const user_base = 0x1000000;

/// TODO: I presume this sstatus is supervisor status.
/// This enables user mode (U-mode).
const sstatus_spie: u32 = 1 << 5;

fn user_entry() callconv(.naked) void {
    // FIXME: In this book, we don't use hardware interrupts but use polling instead, so it's not
    // necessary to set the SPIE bit. However, it's better to be clear rather than silently ignoring
    // interrupts.
    asm volatile (
    // Set the program counter for when transitioning to U-Mode in the sepc register. That is, where
    // sret jumps to.
        \\csrw sepc, %[sepc]
        // Set the SPIE bit in the sstatus register. Setting this enables hardware interrupts when
        // entering U-Mode, and the handler set in the stvec register will be called.
        \\csrw sstatus, %[sstatus]
        // The sret instruction transitions to the user mode if the SPP bit in sstatus is 0.
        \\sret
        :
        : [sepc] "r" (user_base),
          [sstatus] "r" (sstatus_spie),
    );
}

// DISK I/O

const sector_size = 512;
const virtq_entry_num = 16;
const virtio_device_blk = 2;
const virtio_blk_paddr = 0x10001000;
const virtio_reg_magic = 0x00;
const virtio_reg_version = 0x04;
const virtio_reg_device_id = 0x08;
const virtio_reg_queue_sel = 0x30;
const virtio_reg_queue_num_max = 0x34;
const virtio_reg_queue_num = 0x38;
const virtio_reg_queue_align = 0x3c;
const virtio_reg_queue_pfn = 0x40;
const virtio_reg_queue_ready = 0x44;
const virtio_reg_queue_notify = 0x50;
const virtio_reg_device_status = 0x70;
const virtio_reg_device_config = 0x100;
const virtio_status_ack = 1;
const virtio_status_driver = 2;
const virtio_status_driver_ok = 4;
const virtio_status_feat_ok = 8;
const virtq_desc_f_next = 1;
const virtq_desc_f_write = 2;
const virtq_avail_f_no_interrupt = 1;
const virtio_blk_t_in = 0;
const virtio_blk_t_out = 1;

/// Virtqueue Descriptor area entry (2.6.5).
///
/// https://docs.oasis-open.org/virtio/virtio/v1.1/csprd01/virtio-v1.1-csprd01.html#x1-320005
const virtq_desc = extern struct {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
};

/// Virtqueue Available Ring (2.6.6).
///
/// https://docs.oasis-open.org/virtio/virtio/v1.1/csprd01/virtio-v1.1-csprd01.html#x1-380006
const virtq_avail = extern struct {
    flags: u16,
    index: u16,
    ring: [virtq_entry_num]u16,
};

/// Virtqueue Used Ring (2.6.8).
///
/// https://docs.oasis-open.org/virtio/virtio/v1.1/csprd01/virtio-v1.1-csprd01.html#x1-430008
const virtq_used = extern struct {
    flags: u16,
    index: u16,
    ring: [virtq_entry_num]virtq_used_elem,
};

/// Virtqueue Used Ring entry (2.6.8).
///
/// https://docs.oasis-open.org/virtio/virtio/v1.1/csprd01/virtio-v1.1-csprd01.html#x1-430008
const virtq_used_elem = extern struct {
    id: u32,
    len: u32,
};

/// Virtqueue.
const virtio_virtq = struct {
    descs: [virtq_entry_num]virtq_desc,
    avail: virtq_avail,
    used: virtq_used align(page_size_bytes),
    queue_index: i32,
    used_index: *volatile u16,
    last_used_index: u16,
};

/// Virtio-blk request (5.2.6).
///
/// https://docs.oasis-open.org/virtio/virtio/v1.1/csprd01/virtio-v1.1-csprd01.html#x1-2500006
const virtio_blk_req = extern struct {
    // First descriptor: read-only from the device
    type: u32,
    reserved: u32,
    sector: u64,
    // Second descriptor: writable by the device if it's a read operation (VIRTQ_DESC_F_WRITE)
    data: [512]u8,
    // Third descriptor: writable by the device (VIRTQ_DESC_F_WRITE)
    status: u8,
};

fn reg_32_ptr(offset: u32) *volatile u32 {
    const addr = virtio_blk_paddr + @as(usize, offset);
    return @ptrFromInt(addr);
}

fn reg_64_ptr(offset: u32) *volatile u64 {
    const addr = virtio_blk_paddr + @as(usize, offset);
    return @ptrFromInt(addr);
}

fn virtio_reg_32_read(offset: u32) u32 {
    return reg_32_ptr(offset).*; // volatile load
}

fn virtio_reg_64_read(offset: u32) u64 {
    return reg_64_ptr(offset).*; // volatile load
}

fn virtio_reg_32_write(offset: u32, value: u32) void {
    reg_32_ptr(offset).* = value; // volatile store
}

fn virtio_reg_32_fetch_and_or(offset: u32, value: u32) void {
    // FIXME: Same read-modify-write semantics as the C version (not atomic).
    virtio_reg_32_write(offset, virtio_reg_32_read(offset) | value);
}

var blk_request_vq: *virtio_virtq = undefined;
var blk_req: *virtio_blk_req = undefined;
var blk_req_paddr: usize = undefined;
var blk_capacity: u64 = undefined;

fn virtio_blk_init() void {
    if (virtio_reg_32_read(virtio_reg_magic) != 0x74726976)
        @panic("virtio: invalid magic value");
    if (virtio_reg_32_read(virtio_reg_version) != 1)
        @panic("virtio: invalid version");
    if (virtio_reg_32_read(virtio_reg_device_id) != virtio_device_blk)
        @panic("virtio: invalid device id");

    // 1. Reset the device.
    virtio_reg_32_write(virtio_reg_device_status, 0);
    // 2. Set the ACKNOWLEDGE status bit: the guest OS has noticed the device.
    virtio_reg_32_fetch_and_or(virtio_reg_device_status, virtio_status_ack);
    // 3. Set the DRIVER status bit.
    virtio_reg_32_fetch_and_or(virtio_reg_device_status, virtio_status_driver);
    // 5. Set the FEATURES_OK status bit.
    virtio_reg_32_fetch_and_or(virtio_reg_device_status, virtio_status_feat_ok);
    // 7. Perform device-specific setup, including discovery of virtqueues for the device
    blk_request_vq = virtq_init(0);
    // 8. Set the DRIVER_OK status bit.
    virtio_reg_32_write(virtio_reg_device_status, virtio_status_driver_ok);

    // Get the disk capacity.
    blk_capacity = virtio_reg_64_read(virtio_reg_device_config + 0) * sector_size;
    // printf("virtio-blk: capacity is %d bytes\n", (int)blk_capacity);

    // Allocate a region to store requests to the device.
    std.debug.assert(@sizeOf(virtio_blk_req) <= page_size_bytes);
    blk_req_paddr = @intFromPtr(alloc_pages(1).ptr);
    blk_req = @ptrFromInt(blk_req_paddr);
}

fn virtq_init(index: u32) *virtio_virtq {
    // Allocate a region for the virtqueue.
    std.debug.assert(@sizeOf(virtio_virtq) <= page_size_bytes);
    const virtq_paddr: usize = @intFromPtr(alloc_pages(1).ptr);
    const vq: *virtio_virtq = @ptrFromInt(virtq_paddr);
    vq.queue_index = @intCast(index);
    vq.used_index = &vq.used.index;
    // 1. Select the queue writing its index (first queue is 0) to QueueSel.
    virtio_reg_32_write(virtio_reg_queue_sel, index);
    // 5. Notify the device about the queue size by writing the size to QueueNum.
    virtio_reg_32_write(virtio_reg_queue_num, virtq_entry_num);
    // 6. Notify the device about the used alignment by writing its value in bytes to QueueAlign.
    virtio_reg_32_write(virtio_reg_queue_align, 0);
    // 7. Write the physical number of the first page of the queue to the QueuePFN register.
    virtio_reg_32_write(virtio_reg_queue_pfn, virtq_paddr);
    return vq;
}

/// Notifies the device that there is a new request. `desc_index` is the index of the head
/// descriptor of the new request.
fn virtq_kick(vq: *virtio_virtq, desc_index: u16) void {
    // Put head descriptor index into the available ring.
    const ring_index: usize = @as(usize, @intCast(vq.avail.index % virtq_entry_num));
    vq.avail.ring[ring_index] = desc_index;
    vq.avail.index +%= 1; // wrap around u16

    // TODO: There was a __sync_synchronize() here.

    // Notify device about this queue.
    virtio_reg_32_write(virtio_reg_queue_notify, @as(u32, @intCast(vq.queue_index)));

    // Track the last used index we’re expecting the device to catch up to.
    vq.last_used_index +%= 1;
}

// Returns whether there are requests being processed by the device.
fn virtq_is_busy(vq: *virtio_virtq) bool {
    // If the device's used index hasn't reached our last_used_index, there is still a request in
    // flight.
    return vq.last_used_index != vq.used_index.*;
}

// Reads/writes one sector from/to virtio-blk device.
fn read_write_disk(buf: [*]u8, sector: u32, is_write: bool) void {
    const max_sector = blk_capacity / sector_size;

    if (sector >= @as(u32, @intCast(max_sector))) {
        log.err(
            "virtio: tried to read/write sector={d}, but capacity is {d}\n",
            .{ sector, max_sector },
        );
        return;
    }

    // Construct the request according to the virtio-blk specification.
    blk_req.sector = sector;
    blk_req.type = if (is_write) virtio_blk_t_out else virtio_blk_t_in;

    if (is_write) {
        // Copy data from caller buffer into request.
        @memcpy(blk_req.data[0..sector_size], buf[0..sector_size]);
    }

    // Construct the virtqueue descriptors (using 3 descriptors).
    const vq = blk_request_vq;

    // Descriptor 0: request header (type, reserved, sector).
    vq.descs[0].addr = @as(u64, blk_req_paddr);
    vq.descs[0].len = @as(u32, @intCast(@sizeOf(u32) * 2 + @sizeOf(u64)));
    vq.descs[0].flags = virtq_desc_f_next;
    vq.descs[0].next = 1;

    // Descriptor 1: data buffer.
    vq.descs[1].addr = @as(u64, blk_req_paddr + @offsetOf(virtio_blk_req, "data"));
    vq.descs[1].len = @as(u32, sector_size);
    vq.descs[1].flags = virtq_desc_f_next |
        (if (is_write) @as(u16, 0) else virtq_desc_f_write);
    vq.descs[1].next = 2;

    // Descriptor 2: status byte.
    vq.descs[2].addr = @as(u64, blk_req_paddr + @offsetOf(virtio_blk_req, "status"));
    vq.descs[2].len = @as(u32, @intCast(@sizeOf(u8)));
    vq.descs[2].flags = virtq_desc_f_write;

    // Notify the device that there is a new request.
    virtq_kick(vq, 0);

    // Wait until the device finishes processing.
    while (virtq_is_busy(vq)) {}

    // virtio-blk: If a non-zero value is returned, it's an error.
    if (blk_req.status != 0) {
        log.err(
            "virtio: warn: failed to read/write sector={} status={}\n",
            .{ sector, blk_req.status },
        );
        return;
    }

    // For read operations, copy the data into the buffer.
    if (!is_write) {
        @memcpy(buf[0..sector_size], blk_req.data[0..sector_size]);
    }
}
