#ifdef ARCH_X86_64
    .text
    .global ifunc_resolver
ifunc_resolver:
    /* there may be some more registers (e.g. XMM) */
    push    %rax
    push    %rcx
    push    %rdx
    push    %rsi
    push    %rdi
    push    %r8
    push    %r9
    push    %r10
    mov     0x40(%rsp), %rdi
#if 0
    subq    $128, %rsp
    movdqu  %xmm0, (%rsp)
    movdqu  %xmm1, 16(%rsp)
    movdqu  %xmm2, 32(%rsp)
    movdqu  %xmm3, 48(%rsp)
    movdqu  %xmm4, 64(%rsp)
    movdqu  %xmm5, 80(%rsp)
    movdqu  %xmm6, 96(%rsp)
    movdqu  %xmm7, 112(%rsp)
#endif
    call    *ifunc_select@gotpcrel(%rip)
#if 0
    movdqu  (%rsp), %xmm0
    movdqu  16(%rsp), %xmm1
    movdqu  32(%rsp), %xmm2
    movdqu  48(%rsp), %xmm3
    movdqu  64(%rsp), %xmm4
    movdqu  80(%rsp), %xmm5
    movdqu  96(%rsp), %xmm6
    movdqu  112(%rsp), %xmm7
    addq    $128, %rsp
#endif
    pop     %r10
    pop     %r9
    pop     %r8
    pop     %rdi
    pop     %rsi
    pop     %rdx
    pop     %rcx
    pop     %rax
    pop     %r11    # pushed by plt
    jmpq    *(%r11)
    .type ifunc_resolver, STT_FUNC
    .size ifunc_resolver, .-ifunc_resolver
#endif
