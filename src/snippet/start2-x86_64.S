.global _start2
.global egalito_initial_stack
#.global egalito_saved_rdx
.global egalito_entry

.section .bss
egalito_initial_stack:
    .skip   8
#egalito_saved_rdx:
    #.skip   8
egalito_entry:
    .skip   8

.section .text
# This has to be called in the target context
_start2:
    .cfi_startproc
    .cfi_undefined %rip
    push    %rbx                    # keep alignment
    call    *egalito_callInit@gotpcrel(%rip)
    pop     %rbx

    mov     egalito_initial_stack@gotpcrel(%rip), %rax
    mov     (%rax), %rsp            # restore %rsp
    xor     %rdx, %rdx  # clear for now since loader is static

    mov     egalito_entry@gotpcrel(%rip), %rbx
    jmp     *(%rbx)
    hlt
    .cfi_endproc
    .type _start2, STT_FUNC
    .size _start2, .-_start2

