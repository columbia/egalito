.global __libc_start_main
.global main
.global entry

.global _start
.global _start2

.section .bss
initial_stack:
    .skip   8

.section .text

# We only need to preserve %rdx and %rsp, according to
# glibc's sysdeps/x86_64/elf/start.S, which cites the SVR4/i386 ABI.
_start:
    xor     %rbp, %rbp
    mov     %rsp, initial_stack     # save top of stack

    pop     %rsi
    mov     %rsp, %rdx
    and     $~15,%rsp
    push    %rsi  # junk

    push    %rsp

    #mov     0x8(%rsp), %rdi         # set argc
    #lea     0x10(%rsp), %rsi        # set argv

    mov     $__libc_csu_fini, %r8
    mov     $__libc_csu_init, %rcx
    mov     $main, %rdi

    mov     %rsp, %rbp
    call    __libc_start_main@plt   # this does not return
    hlt

_start2:
    mov     initial_stack, %rsp     # restore %rsp

    mov     entry, %rbx
    pop     %rdx                    # restore %rdx

    jmp     *%rbx                   # jump to entry point

.section    .note.GNU-stack, "", @progbits

