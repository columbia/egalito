.global _start
.global _start2
.global entry
.global initial_stack

.section .bss
initial_stack:
    .skip   8
saved_rdx:
    .skip   8
entry:
    .skip   8

.section .text

# We only need to preserve %rdx and %rsp, according to
# glibc's sysdeps/x86_64/elf/start.S, which cites the SVR4/i386 ABI.
_start:
    .cfi_startproc
    .cfi_undefined %rip
    xor     %rbp, %rbp
    mov     %rsp, initial_stack     # save top of stack
    mov     %rdx, saved_rdx

    # Set up arguments for __libc_start_main, on the stack and in registers:
    #   main:       %rdi
    #   argc:       %rsi
    #   argv:       %rdx
    #   init:       %rcx
    #   fini:       %r8
    #   rtld_fini:  %r9
    #   stack_end:  stack
    mov     %rdx, %r9               # library termination function
    pop     %rsi                    # argc
    mov     %rsp, %rdx              # argv

    and     $~15, %rsp              # round stack pointer

    push    %rsi                    # place argc back
    push    %rsp                    # make stack frame

    mov     $__libc_csu_fini, %r8
    mov     $__libc_csu_init, %rcx
    mov     $main, %rdi

    mov     %rsp, %rbp
    call    __libc_start_main@plt   # this does not return
    hlt
    .cfi_endproc

_start2:
    .cfi_startproc
    .cfi_undefined %rip
    mov     initial_stack, %rsp     # restore %rsp
    mov     saved_rdx, %rdx         # restore %rdx

    ##pop     %r9                     # get argc
    ##dec     %r9                     # subtract from argc
    ##pop     %r10                    # remove loader from argv array
    ##push    %r9                     # put argc back

    mov     entry, %rbx
    jmp     *%rbx                   # jump to entry point
    hlt
    .cfi_endproc

.section    .note.GNU-stack, "", @progbits

