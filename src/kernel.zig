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
// - Get assertions working (we're using ReleaseSmall).
// - Unreachable should print something sensible? I assume it doesn't because we've redefined panic.

const std = @import("std");

// Symbols from the linker script.
const kernel_base = @extern([*]u8, .{ .name = "__kernel_base" }); // start of kernel memory
const bss = @extern([*]u8, .{ .name = "__bss" });
const bss_end = @extern([*]u8, .{ .name = "__bss_end" });
const stack_top = @extern([*]u8, .{ .name = "__stack_top" });
const ram_start = @extern([*]u8, .{ .name = "__free_ram" });
const ram_end = @extern([*]u8, .{ .name = "__free_ram_end" });

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
/// to jump here and the C ABI doesn't speak Zig errors we just use this function to bridge the gap.
/// We catch and print any errors here so that we can use `try` in main.
export fn kernel_main() noreturn {
    // TODO: Replace this with try.
    main() catch |err| std.debug.panic("{s}\n", .{@errorName(err)});
    unreachable;
}

/// The kernel main function.
fn main() !void {
    // Ensure the bss section is cleared to zero.
    @memset(bss[0 .. bss_end - bss], 0);

    write_csr("stvec", @intFromPtr(&kernel_entry));

    try console.print("\n\nHello {s}\n\n", .{"Kernel!"});

    {
        const page1 = alloc_pages(2);
        const page2 = alloc_pages(1);

        try console.print("alloc_pages test: page1={*} ({})\n", .{ page1.ptr, page1.len });
        try console.print("alloc_pages test: page2={*} ({})\n", .{ page2.ptr, page2.len });
    }

    {
        //
        process_idle = create_process(undefined);
        process_current = process_idle;

        _ = create_process(&process_a_entry);
        _ = create_process(&process_b_entry);

        //
        yield();

        @panic("Switched to idle process!\n");
    }

    while (true) asm volatile ("");
}

// SUPERVISOR BINARY INTERFACE (SBI) CALLS

const SbiRet = struct {
    err: usize,
    value: usize,
};

/// Perform an Environment Call (ECAll) using the Supervisor Binary Interface (SBI). This is used
/// to implement a syscall: a call from user mode to execute higher privileged code.
pub fn sbi_call(
    arg0: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
    arg5: usize,
    fid: usize,
    eid: usize,
) SbiRet {
    var err: usize = undefined;
    var value: usize = undefined;

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

// SERIAL CONSOLE

fn write_fn(_: *const anyopaque, bytes: []const u8) !usize {
    for (bytes) |c| _ = sbi_call(c, 0, 0, 0, 0, 0, 0, 1);
    return bytes.len;
}

const console: std.io.AnyWriter = .{
    .context = undefined,
    .writeFn = write_fn,
};

/// The panic handler. Just prints the message to the console and stalls the program. By default Zig
/// uses the panic handler defined in the root of the executable.
pub fn panic(
    msg: []const u8,
    error_return_trace: ?*std.builtin.StackTrace,
    ret_addr: ?usize,
) noreturn {
    _ = error_return_trace;
    _ = ret_addr;

    console.print("PANIC: {s}", .{msg}) catch {};
    while (true) asm volatile ("");
}

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

export fn handle_trap(_: *TrapFrame) void {
    const scause = read_csr("scause");
    const stval = read_csr("stval");
    const user_pc = read_csr("sepc");

    std.debug.panic(
        "Unexpected trap scause={x}, stval={x}, user_pc={x}\n",
        .{ scause, stval, user_pc },
    );
}

/// Read control and status register (CSR)
fn read_csr(comptime register: []const u8) usize {
    return asm volatile ("csrr %[ret], " ++ register
        : [ret] "=r" (-> usize),
    );
}

/// Write control and status register (CSR)
fn write_csr(comptime register: []const u8, val: usize) void {
    asm volatile ("csrw " ++ register ++ ", %[val]"
        :
        : [val] "r" (val),
    );
}

// MEMORY ALLOCATION

var ram_used_bytes: usize = 0;
const page_size_bytes = 4096;

/// A simple bump allocator.
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

    // console.print(
    //     "Memory available: {} bytes. Allocating {} pages. Remaining after allocation: {} bytes\n",
    //     .{ ram_available.len, pages, ram_available.len - ram_used_bytes },
    // ) catch {};

    return result;
}

// PROCESSES

const Process = struct {
    /// The conventional name for the process ID.
    pid: u32,
    state: enum { unused, runnable },
    /// The conventional name for the stack pointer.
    sp: usize,
    /// Pointer to the first-level page table, the page directory.
    page_directory: [*]PageTableEntry,
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
fn create_process(entrypoint: *const anyopaque) *Process {
    const process = for (&processes, 0..) |*process, pid| {
        if (process.state == .unused) {
            process.pid = pid;
            break process;
        }
    } else @panic("No free process slots\n");

    // Reserve space for the callee-saved registers on the stack. s0-s11 are zero-initialised and ra
    // is set to the process entrypoint. These will be restored in the first context switch. sp is
    // stored in the Process struct and points to the bottom of stack (which will hold ra).
    const registers = blk: {
        // Get the stack as a []usize from []u8 because we're working with registers.
        const ptr: [*]usize = @ptrCast(@alignCast(&process.stack));
        const stack = ptr[0 .. process.stack.len / @sizeOf(usize)];

        const registers = stack[stack.len - 13 ..]; // 14 callee-saved registers (-1 for sp)
        for (registers[1..]) |*register| register.* = 0; // s0-s11
        registers[0] = @intFromPtr(entrypoint); // ra

        break :blk registers;
    };

    // Map kernel pages.
    const page_directory_buffer = alloc_pages(1);
    const page_directory: [*]PageTableEntry = @ptrCast(@alignCast(page_directory_buffer.ptr));

    var paddr: usize = @intFromPtr(kernel_base);
    while (paddr < @intFromPtr(&ram_end[0])) : (paddr += page_size_bytes) {
        // console.print("paddr: {*}\n", .{paddr}) catch {};
        map_page(page_directory, @bitCast(paddr), paddr, .{
            .readable = true,
            .writable = true,
            .executable = true,
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
noinline fn yield() void {
    // Process.pid is also the index of the process so we can loop through pid offsets (wrapping
    // around with % process.len) until we've checked all the processes including the current
    // process.
    const process_next = for (1..processes.len + 1) |i| {
        const process = &processes[(process_current.pid + i) % processes.len];
        if (process.state == .runnable and process.pid > 0) break process;
    } else process_idle;

    if (process_next == process_current) return;

    asm volatile (
        \\sfence.vma
        \\csrw satp, %[satp]
        \\sfence.vma
        \\csrw sscratch, %[sscratch]
        :
        : [satp] "r" (satp | (@intFromPtr(&process_next.page_directory[0]) / page_size_bytes)),
          [sscratch] "r" (@intFromPtr(process_next.stack[0..].ptr) + process_next.stack.len),
    );

    const previous = process_current;
    process_current = process_next;
    switch_context(&previous.sp, &process_next.sp);
}

/// Context switch between processes. Saves the current process's registers onto the kernel-reserved
/// space on its stack, swaps the stack pointers, then restores the next process's registers from
/// its kernel-reserved stack space. That is, a process's execution context is stored as temporary
/// local variables on it's stack (Process.stack).
noinline fn switch_context(sp_addr_prev: *usize, sp_addr_next: *usize) void {
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

        // Switch the stack pointer.
        \\sw sp, (%[sp_addr_prev]) // *sp_addr_prev = sp
        \\lw sp, (%[sp_addr_next]) // sp = *sp_addr_next

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
        :
        : [sp_addr_prev] "r" (sp_addr_prev),
          [sp_addr_next] "r" (sp_addr_next),
    );
}

fn delay() void {
    for (0..1_000_000_000) |_| asm volatile ("nop");
}

export fn process_a_entry() void {
    console.print("\nStarting process A\n", .{}) catch {};
    while (true) {
        console.print("A", .{}) catch {};
        delay();
        yield();
    }
}

export fn process_b_entry() void {
    console.print("\nStarting process B\n", .{}) catch {};
    while (true) {
        console.print("B", .{}) catch {};
        delay();
        yield();
    }
}

// PAGE TABLE

// NOTE: We're using Sv32 which (I think) stands for [S]upervisor-mode [V]irtual memory with 32-bit
// virtual addresses. It uses a two-level page table. The 32-bit virtual address is divided into a
// first-level page table index (VPN[1]), a second-level page table index (VPN[0]), and a page
// offset. That's right, they call the first-level page table table1 and the second-level page table
// table0... I think it's because to get a physical address from a virtual address you index the
// first-level page table before the second-level page table.

const VirtualAddress = packed struct(u32) {
    /// The page offset indexes bytes in a page (it's 12 bits because a page is 2^12=4096 bytes).
    offset: u12,
    /// Index into the second-level page table (table0). This index is referred to as VPN[2]: the
    /// [V]irtual [P]age [N]umber of the [2]nd-level page table.
    vpn0: u10,
    /// Index into the first-level page table (the page directory, table1). This index is referred
    /// to as VPN[1]: the [V]irtual [P]age [N]umber of the [1]st-level page table.
    vpn1: u10,
};

/// Supervisor Address Translation and Protection CSR.
// const Satp = packed struct(u32) {
//     reserved: u31 = undefined,
//     /// Enables paging in Sv32 mode.
//     sv32: bool,
// };
//
// const satp: Satp = .{ .sv32 = true };
const satp: usize = 1 << 31;

/// This struct is basically just an address with some metadata stuffed in. Because all of the
/// addresses stored in page table entries are 4 KiB (4096) aligned, they always ends with 12 zeroes
/// (2^12 = 4096). Don't fully get this yet but we get rid of the zeroes by diving by the page table
/// size. This gives us the page table number. This is then stored in the top 22 bits, leaving 10
/// bits for metadata. (Why store the address in the top 22 bits if only 20 bits of it are
/// non-zero?)
const PageTableEntry = packed struct(u32) {
    valid: bool = false, // entry enabled
    readable: bool = false,
    writable: bool = false,
    executable: bool = false,
    user: bool = false, // accessible in user mode
    _: u5 = undefined,
    /// Physical page number (PPN): If this is a page directory entry this points to a page table.
    /// If this is a page table entry this points to the page being looked up.
    ppn: u22 = undefined,

    fn addr(entry: PageTableEntry) usize {
        return entry.ppn * page_size_bytes;
    }
};

/// There are 1024 entries in the page directory, a.k.a. the first-level page table. It takes up
/// 4096 bytes (i.e. a page's-worth): 1024 32-bit entries. Each entry points to a (second-level)
/// page table that also contains 1024 entries (another 4096 bytes). Each of those entries point to
/// a physical page.
fn map_page(
    page_directory: [*]PageTableEntry,
    vaddr: usize,
    paddr: usize,
    flags: PageTableEntry, // entry with just flags initialised
) void {
    // The virtual and physical addresses must be aligned to the page size.
    if (vaddr % page_size_bytes != 0) std.debug.panic("unaligned vaddr ({})", .{vaddr});
    if (paddr % page_size_bytes != 0) std.debug.panic("unaligned paddr ({})", .{paddr});

    const virtual_address: VirtualAddress = @bitCast(vaddr);

    var page_directory_entry = &page_directory[virtual_address.vpn1]; // first-level page table entry
    // Initialise the 1st-level page table entry if it doesn't exist: allocate a page to store the
    // second-level page table.
    if (!page_directory_entry.valid) {
        // Allocate memory for the (second-level) page table.
        const page_table_bytes = alloc_pages(1);
        // Store the address of the page table as a PPN (i.e. a multiple of the page size).
        page_directory_entry.ppn = @intCast(@intFromPtr(page_table_bytes.ptr) / page_size_bytes);
        page_directory_entry.valid = true;
    }

    // Set the 2nd-level page table entry to map the physical page.
    const page_table: [*]PageTableEntry = @ptrFromInt(page_directory_entry.addr());
    var page_table_entry = &page_table[virtual_address.vpn0];
    page_table_entry.valid = true;
    page_table_entry.readable = flags.readable;
    page_table_entry.writable = flags.writable;
    page_table_entry.executable = flags.executable;
    page_table_entry.user = flags.user;
    // Store the address of the physical page as a PPN.
    page_table_entry.ppn = @intCast(paddr / page_size_bytes);
}
