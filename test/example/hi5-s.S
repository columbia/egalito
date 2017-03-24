.global my_write
.global my_exit
my_write:
#ifdef ARCH_X86_64
    push    %rcx
    push    %r11
    mov     $1, %rax    # write
    syscall             # other args in %rdi, %rsi, %rdx
    pop     %r11
    pop     %rcx
    retq
#elif defined(ARCH_AARCH64)
    mov     x8, 64
    svc     0
    ret
#endif
.type my_write, @function
.size my_write, .-my_write
my_exit:
#ifdef ARCH_X86_64
    mov     $60, %rax   # exit
    syscall
#elif defined(ARCH_AARCH64)
    mov     x8, 93
    svc     0
    ret
#endif
.type my_exit, @function
.size my_exit, .-my_exit
