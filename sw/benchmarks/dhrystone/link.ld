/* Linker script for ANT-V cve2_riscv_compliance simulation */
OUTPUT_ARCH(riscv)

MEMORY
{
    ram   : ORIGIN = 0x00000000, LENGTH = 0x0E000 /* 56 kB */
    stack : ORIGIN = 0x0000E000, LENGTH = 0x02000 /* 8 kB */
}

_stack_start = ORIGIN(stack) + LENGTH(stack);

_entry_point = 0x80;
ENTRY(_entry_point)

SECTIONS
{
    .vectors :
    {
        . = ALIGN(4);
        KEEP(*(.vectors))
    } > ram

    .text : {
        . = ALIGN(4);
        *(.text)
        *(.text.*)
    } > ram

    .rodata : {
        . = ALIGN(4);
        *(.rodata)
        *(.rodata.*)
        *(.srodata)
        *(.srodata.*)
    } > ram

    .data : {
        . = ALIGN(4);
        *(.data)
        *(.data.*)
        *(.sdata)
        *(.sdata.*)
    } > ram

    .bss :
    {
        . = ALIGN(4);
        _bss_start = .;
        *(.bss)
        *(.bss.*)
        *(.sbss)
        *(.sbss.*)
        *(COMMON)
        _bss_end = .;
    } > ram
}

