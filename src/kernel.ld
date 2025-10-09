ENTRY(boot)

SECTIONS {
    . = 0x80200000;
    __kernel_base = .;

    .text :{
        KEEP(*(.text.boot));
        *(.text .text.*);
    }

    .rodata : ALIGN(4) {
        *(.rodata .rodata.*);

        /* Let's tell the linker script to fill the "reserved" bytes with 0xAA. That's handy because
         * our bespoke tool can check it's only replacing 0xAA bytes, as a sanity check that it's
         * doing the right thing.
         *
         * The documentation will tell you that you can just write 0xAA, but that seems to be a lie:
         * we need `0xAAAAAAAA`. Might just be a bug in LLVM's implementation, idk. */
        FILL(0xAAAAAAAA);

        /* '.' means "the current address". The pattern here is that we set a symbol to that address
         * and then offset our address by the number of bytes we need to reserve.
         *
         * The order in which we allocate the sections here must remain in sync with a section list
         * in the aforementioned bespoke tool. */
        __debug_info        = .; . += SIZEOF(.debug_info);
        __debug_abbrev      = .; . += SIZEOF(.debug_abbrev);
        __debug_str         = .; . += SIZEOF(.debug_str);
        __debug_str_offsets = .; . += SIZEOF(.debug_str_offsets);
        __debug_line        = .; . += SIZEOF(.debug_line);
        __debug_line_str    = .; . += SIZEOF(.debug_line_str);
        __debug_ranges      = .; . += SIZEOF(.debug_ranges);
        __debug_loclists    = .; . += SIZEOF(.debug_loclists);
        __debug_rnglists    = .; . += SIZEOF(.debug_rnglists);
        __debug_addr        = .; . += SIZEOF(.debug_addr);
        __debug_names       = .; . += SIZEOF(.debug_names);

        /* We also need to tell the binary how long each of those sections is. By the way, I could have
         * written these inside the `.rodata` block above, or before it, or really anywhere inside this
         * file; we're not changing '.' here, just doing symbol assignments, and those can go anywhere. */
        __debug_info_len        = SIZEOF(.debug_info);
        __debug_abbrev_len      = SIZEOF(.debug_abbrev);
        __debug_str_len         = SIZEOF(.debug_str);
        __debug_str_offsets_len = SIZEOF(.debug_str_offsets);
        __debug_line_len        = SIZEOF(.debug_line);
        __debug_line_str_len    = SIZEOF(.debug_line_str);
        __debug_ranges_len      = SIZEOF(.debug_ranges);
        __debug_loclists_len    = SIZEOF(.debug_loclists);
        __debug_rnglists_len    = SIZEOF(.debug_rnglists);
        __debug_addr_len        = SIZEOF(.debug_addr);
        __debug_names_len       = SIZEOF(.debug_names);
    }


    .data : ALIGN(4) {
        *(.data .data.*);
    }

    .bss : ALIGN(4) {
        __bss = .;
        *(.bss .bss.* .sbss .sbss.*);
        __bss_end = .;
    }

    . = ALIGN(4);
    . += 128 * 1024; /* 128 KiB */
    __stack_top = .;

    . = ALIGN(4096);
    __free_ram = .;
    . += 64 * 1024 * 1024; /* 64 MiB */
    __free_ram_end = .;
}
