/*
 * stub.ld — link the stub into a single R+X image based at vaddr 0 so that, after
 * `objcopy -O binary`, every symbol's value equals its byte offset in the flat blob.
 * The injector loads that blob verbatim, so all intra-blob references must be
 * PC-relative (no GOT, no dynamic relocations). We DISCARD unwind/dynamic cruft and
 * rely on the build script to fail if any GOT/relocation survives.
 */
ENTRY(sopk_entry)

SECTIONS
{
    . = 0;
    .text : { *(.text .text.*) }
    .rodata : { *(.rodata .rodata.*) }
    .sopk_info : { KEEP(*(.sopk_info)) }

    /DISCARD/ : {
        *(.comment)
        *(.note .note.*)
        *(.eh_frame) *(.eh_frame_hdr)
        *(.ARM.exidx*) *(.ARM.extab*)
    }
}
