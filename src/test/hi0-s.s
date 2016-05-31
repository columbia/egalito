.global my_write
my_write:
    push    %rcx
    push    %r11
    mov     $1, %rax    # write
    syscall             # other args in %rdi, %rsi, %rdx
    pop     %r11
    pop     %rcx
    retq
.type my_write, @function
.size my_write, .-my_write
