# For sandbox enforcement, we turn each syscall instruction into this sequence.
# See pass/syscallsandbox.cpp.
# Note: this file is not linked in, we just include it here for reference.
# Note: we don't save %xmm0 etc because functions with syscalls don't use them.
    push    %rdi
    mov     %rsp, %rdi
    and     $-0x10, %rsp
    push    %rdi
    push    %rsi
    push    %rdx
    push    %r10
    push    %r8
    push    %r9
    push    %rcx
    mov     %r10, %rcx
    push    %rax
    nop     ; call enforce
    mov     %rax, %r11
    pop     %rax
    pop     %rcx
    pop     %r9
    pop     %r8
    pop     %r10
    pop     %rdx
    pop     %rsi
    pop     %rdi
    mov     %rdi, %rsp
    pop     %rdi
    test    %r11, %r11
    jz      skip
    syscall
skip:
    nop
