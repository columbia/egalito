.global __libc_start_main
.global main
.global entry

.global _start
.global _start2

.section .bss
initial_stack:
    .skip   8
saved_rdx:
    .skip   8

.section .text

# We only need to preserve %rdx and %rsp, according to
# glibc's sysdeps/x86_64/elf/start.S, which cites the SVR4/i386 ABI.
_start:
    xor     %rbp, %rbp

    mov     %rdx, saved_rdx
    mov     %rdx, %r9               # library termination function
    pop     %rsi                    # argc
    mov     %rsp, %rdx              # argv

    and     $~15, %rsp
    mov     %rsp, initial_stack     # save top of stack

    push    %rsi                    # place argc back
    push    %rsp                    # make stack frame

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
    ##pop     %rdx                    # restore %rdx
    ##clr     %rdx                    # no term func
    mov     saved_rdx, %rdx         # restore %rdx
    ##pop     %r9                     # get argc
    ##dec     %r9                     # subtract from argc
    ##pop     %r10                    # remove loader from argv array
    ##push    %r9                     # put argc back

    jmp     *%rbx                   # jump to entry point
what:
    jmp     what

#main2:
#    sub     $1, %rdi        # subtract from argc
#    add     $8, %rsi        # and remove loader from argv array
#    jmp     main

.section    .note.GNU-stack, "", @progbits

