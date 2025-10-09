//! This is the bespoke script which finds the DWARF sections and copies them all to where we want
//! them in the `.rodata` section. It's quite primitive, but works fine for ClashOS at least! I'm
//! not going to explain this toooo in-depth; if you want to understand it you'll need to know a bit
//! about how ELF files are structured, feel free to ask me.

// zig fmt: off
/// You might need to modify this, since RISC-V binaries might have some slightly different fields
/// here compared to AArch64 binaries.
const expect_e_ident: *const [16]u8 = &.{
    0x7F, 'E', 'L', 'F',
    std.elf.ELFCLASS32,
    std.elf.ELFDATA2LSB,
    1, // EI_VERSION
    @intFromEnum(std.elf.OSABI.NONE),
    0, // EI_ABIVERSION
    0, 0, 0, 0, 0, 0, 0, // EI_PAD
};
// zig fmt: on

const word_size = 32;

pub fn main() void {
    var arena_state: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const args = std.process.argsAlloc(arena) catch |err| fatal("failed to alloc args: {t}", .{err});

    if (args.len != 3) fatal("usage: inject_debug_info out.elf in.elf", .{});

    const out_path = args[1];
    const in_path = args[2];

    const bytes = std.fs.cwd().readFileAlloc(in_path, arena, .unlimited) catch |err| fatal("failed to read input file: {t}", .{err});

    if (!std.mem.startsWith(u8, bytes, expect_e_ident)) fatal("e_ident mismatch", .{});
    if (bytes.len < 64) fatal("incomplete elf header", .{});
    // Grab some fields from the ELF header
    const e_shoff = readInt(u32, bytes[32..][0..4], .little);
    const e_shentsize = readInt(u16, bytes[46..][0..2], .little);
    const e_shnum = readInt(u16, bytes[48..][0..2], .little);
    const e_shstrndx = readInt(u16, bytes[50..][0..2], .little);

    if (e_shstrndx >= e_shnum) fatal("e_shstrndx out of bounds", .{});
    if (e_shentsize < word_size) fatal("e_shentsize too small", .{});

    // Look at the "section headers", which define all of the sections in the ELF
    const shdr_bytes_len = e_shentsize * e_shnum;
    if (bytes.len < e_shoff + shdr_bytes_len) fatal("invalid section header table", .{});
    const shdr_bytes = bytes[e_shoff..][0..shdr_bytes_len];

    // Find the string table, or rather the "section header string table"; this is a section we need
    // to use in order to find the names of all other sections (it's a bit funky!)
    const strtab_shdr = shdr_bytes[e_shstrndx * e_shentsize ..][0..e_shentsize];
    const strtab = sectionContents(bytes, strtab_shdr, "(string table)");

    // The order of this slice must remain in sync with the space-allocation logic in `kernel.ld`.
    const debug_names: []const []const u8 = &.{
        ".debug_info",
        ".debug_abbrev",
        ".debug_str",
        ".debug_str_offsets",
        ".debug_line",
        ".debug_line_str",
        ".debug_ranges",
        ".debug_loclists",
        ".debug_rnglists",
        ".debug_addr",
        ".debug_names",
    };
    // We're now going to find the data of all of the debug sections, and of `.rodata`. Then we'll
    // copy the data from the debug sections into `.rodata`, and save the modified file to disk.
    var rodata_contents: ?[]u8 = null;
    var debug_contents: [debug_names.len]?[]const u8 = @splat(null);
    for (0..e_shnum) |i| {
        const shdr = shdr_bytes[i * e_shentsize ..][0..e_shentsize];
        const sh_name = readInt(u32, shdr[0..4], .little);
        if (sh_name > strtab.len) fatal("sh_name out of bounds", .{});
        const name = std.mem.sliceTo(strtab[sh_name..], 0);
        if (std.mem.eql(u8, name, ".rodata")) {
            rodata_contents = sectionContents(bytes, shdr, name);
        } else for (debug_names, &debug_contents) |target_name, *contents| {
            if (std.mem.eql(u8, name, target_name)) {
                contents.* = sectionContents(bytes, shdr, name);
            }
        }
    }
    if (rodata_contents == null) fatal("section '.rodata' missing", .{});
    // Insert the sections, in reverse, starting from the *end* of `.rodata` (since that's what our
    // linker script does). If you wanted, you could change the linker script to put them at the
    // start of the section and change this logic to insert *in order* at the *start* of `.rodata`.
    var offset = rodata_contents.?.len;
    var i: usize = debug_names.len;
    while (i > 0) {
        i -= 1;
        const debug_data = debug_contents[i] orelse continue; // debug info may be omitted; even if not, some sections may not be used
        const dest = rodata_contents.?[offset - debug_data.len ..][0..debug_data.len];
        if (!std.mem.allEqual(u8, dest, 0xAA)) fatal("section '{s}' would replace non-0xAA bytes in '.rodata'", .{debug_names[i]});
        @memcpy(rodata_contents.?[offset - debug_data.len ..][0..debug_data.len], debug_data);
        offset -= debug_data.len;
    }

    std.fs.cwd().writeFile(.{ .sub_path = out_path, .data = bytes }) catch |err| fatal("failed to write output file: {t}", .{err});
}

fn sectionContents(bytes: []u8, shdr: []const u8, name: []const u8) []u8 {
    const sh_flags = readInt(u32, shdr[8..][0..4], .little);
    const sh_offset = readInt(u32, shdr[16..][0..4], .little);
    const sh_size = readInt(u32, shdr[20..][0..4], .little);
    if (sh_flags & std.elf.SHF_COMPRESSED != 0) fatal("section '{s}' compressed", .{name});
    if (sh_offset + sh_size >= bytes.len) fatal("section '{s}' data out of bounds", .{name});
    return bytes[sh_offset .. sh_offset + sh_size];
}

const std = @import("std");
const fatal = std.process.fatal;
const readInt = std.mem.readInt;
