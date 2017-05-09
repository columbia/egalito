.global entry
.global initial_stack
.global _start2

.section .bss
.align 8
initial_stack:
    .skip   8
entry:
    .skip   8

    .text
    .globl _start
    .type _start,#function
_start:

_start2:
