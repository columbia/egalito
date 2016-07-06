.global my_write
.global my_exit
my_write:
    push    %rcx
    push    %r11
    mov     $1, %rax    # write
    syscall             # other args in %rdi, %rsi, %rdx
    pop     %r11
    pop     %rcx
    retq
my_exit:
    mov     $60, %rax   # exit
    syscall
.type my_write, @function
.size my_write, .-my_write
