/* Startup and vector table for ANT-V cve2_riscv_compliance simulation */
.section .vectors, "ax"
.option norvc;

.org 0x00
.rept 32
jal x0, reset_handler
.endr

.org 0x80
jal x0, reset_handler

.section .text
reset_handler:
  /* zero all registers */
  mv  x1, x0
  mv  x2, x0
  mv  x3, x0
  mv  x4, x0
  mv  x5, x0
  mv  x6, x0
  mv  x7, x0
  mv  x8, x0
  mv  x9, x0
  mv x10, x0
  mv x11, x0
  mv x12, x0
  mv x13, x0
  mv x14, x0
  mv x15, x0
  mv x16, x0
  mv x17, x0
  mv x18, x0
  mv x19, x0
  mv x20, x0
  mv x21, x0
  mv x22, x0
  mv x23, x0
  mv x24, x0
  mv x25, x0
  mv x26, x0
  mv x27, x0
  mv x28, x0
  mv x29, x0
  mv x30, x0
  mv x31, x0

  /* stack pointer */
  la sp, _stack_start

  /* zero bss */
  la t0, _bss_start
  la t1, _bss_end
1:
  bge t0, t1, 2f
  sw zero, 0(t0)
  addi t0, t0, 4
  j 1b
2:
  call main

  /* Signal simulation finish to testutil (address 0x20000) */
  li t0, 0x20000
  sw a0, 0(t0)

3:
  wfi
  j 3b

