/// RISC-V toy kernel based on the book 'OS in 1,000 Lines'

// Some inline assembly is used. The docs are here:
// https://ziglang.org/documentation/master/#toc-Assembly

// TODO:
// - get assertions working

const std = @import("std");

const bss = @extern([*]u8, .{ .name = "__bss" });
const bss_end = @extern([*]u8, .{ .name = "__bss_end" });
const stack_top = @extern([*]u8, .{ .name = "__stack_top" });
const ram_start = @extern([*]u8, .{ .name = "__free_ram" });
const ram_end = @extern([*]u8, .{ .name = "__free_ram_end" });

export fn kernel_main() noreturn {
    // Ensure the bss section is cleared to zero.
    @memset(bss[0 .. bss_end - bss], 0);

    write_csr("stvec", @intFromPtr(&kernel_entry));

    console.print("\n\nHello {s}\n", .{"World!"}) catch {};

    const paddr0 = alloc_pages(2);
    const paddr1 = alloc_pages(1);

    console.print("alloc_pages test: paddr0={x}\n", .{@intFromPtr(paddr0.ptr)}) catch {};
    console.print("alloc_pages test: paddr1={x}\n", .{@intFromPtr(paddr1.ptr)}) catch {};

    @panic("Booted!\n");

    // while (true) asm volatile ("");
}

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

export fn boot() linksection(".text.boot") callconv(.Naked) void {
    asm volatile (
        \\mv sp, %[stack_top]
        \\j kernel_main
        :
        : [stack_top] "r" (stack_top),
    );
}

var ram_used: usize = 0;

/// A simple bump allocator.
///
/// TODO: Support freeing memory. Consider a bitmap-based algorithm or the "buddy system".
fn alloc_pages(pages: usize) []u8 {
    const page_size = 4096;
    const ram: []u8 = ram_start[0 .. ram_end - ram_start];

    const alloc_size = pages * page_size;
    const ram_available = ram[ram_used..];

    if (alloc_size > ram_available.len) @panic("Out of memory");

    const result = ram_available[0..alloc_size];
    @memset(result, 0);
    ram_used += alloc_size;

    return result;
}

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
        : "memory"
    );

    return .{ .err = err, .value = value };
}

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

// Preserves the CPU state by saving all general-purpose registers.
//
// RISC-V defines 32 integer registers. The first integer register is a zero register, and the
// remainder are general-purpose registers. The kernel allocates extra stack space to store the
// general purpose registers in the format described by the TrapFrame structure. `handle_trap` is
// passed a pointer to this structure and handles the exception logic The CPU state is then restored
// and execution is resumed.
export fn kernel_entry() align(4) callconv(.Naked) void {
    asm volatile (
    // Store the original stack pointer in sscratch so that the kernel can allocate its own
    // private stack (requiring sp).
        \\csrw sscratch, sp

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

        // Store the original sp at the end of the space we allocated (you can see it's the last
        // item in TrapFrame).
        \\csrr a0, sscratch
        \\sw a0, 4 * 30(sp)

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

const console: std.io.AnyWriter = .{
    .context = undefined,
    .writeFn = write_fn,
};

fn write_fn(_: *const anyopaque, bytes: []const u8) !usize {
    for (bytes) |c| _ = sbi_call(c, 0, 0, 0, 0, 0, 0, 1);
    return bytes.len;
}
