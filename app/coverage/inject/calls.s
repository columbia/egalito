.global shmat
.global shmdt
.global exit
.global write
.global __mmap
.hidden shmat
.hidden shmdt
.hidden exit
.hidden write
.hidden __mmap

.section .text

exit:
    mov     $60, %rax   # exit
    syscall             # other arg in %rdi
    hlt

shmat:
    push    %rcx
    push    %r11
    mov     $30, %rax   # shmat
    syscall             # other args in %rdi, %rsi, %rdx
    pop     %r11
    pop     %rcx
    retq

shmdt:
    push    %rcx
    push    %r11
    mov     $67, %rax   # shmdt
    syscall             # other arg in %rdi
    pop     %r11
    pop     %rcx
    retq

write:
    push    %rcx
    push    %r11
    mov     $1, %rax    # write
    syscall             # other args in %rdi, %rsi, %rdx
    pop     %r11
    pop     %rcx
    retq

__mmap:
    push    %rcx
    push    %r11
    push    %rcx
    mov     %r10, %rcx
    pop     %r10
    mov     $9, %rax    # mmap
    syscall             # other args in everything
    pop     %r11
    pop     %rcx
    retq
.size __mmap, .-__mmap
