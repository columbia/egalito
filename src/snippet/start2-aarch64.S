.global _start2
.global egalito_initial_stack
.global egalito_entry

.section .bss
.align 8
egalito_initial_stack:
    .skip   8
egalito_entry:
    .skip   8

.section .text
# This has to be called in the target context
_start2:
    .cfi_startproc
    bl      egalito_callInit

    adrp    x1, :got:egalito_initial_stack
    ldr     x1, [x1, #:got_lo12:egalito_initial_stack]
    ldr     x1, [x1]
    mov     sp, x1
    mov     x0, #0
    adrp    x1, :got:egalito_entry
    ldr     x1, [x1, #:got_lo12:egalito_entry]
    ldr     x1, [x1]
    br      x1
    bl      abort
    .cfi_endproc
    .type _start2, STT_FUNC
    .size _start2, .-_start2
