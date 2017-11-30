    .text
    .global ifunc_resolver
ifunc_resolver:
#ifdef ARCH_X86_64
    /* this isn't a context switch; so save registers manually */
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
    call    *ifunc_select@gotpcrel(%rip)
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
#elif defined(ARCH_AARCH64)
    brk     0   /* NYI */
#endif
    .type ifunc_resolver, STT_FUNC
    .size ifunc_resolver, .-ifunc_resolver
