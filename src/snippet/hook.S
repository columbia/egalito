    .text
    .global egalito_hook_function_entry
egalito_hook_function_entry:
#ifdef ARCH_X86_64
    mov     egalito_inside_hook_code@gotpcrel(%rip), %rax
    cmpb    $0x0, (%rax)
    jne     1f
    push    %rbx
    mov     %rax, %rbx
    movb    $0x1, (%rax)
    mov     0x8(%rsp), %rdi
    mov     egalito_hook_function_entry_hook@gotpcrel(%rip), %rax
    callq   *(%rax)
    movb    $0x0, (%rbx)
    pop     %rbx
1:
    retq
#elif defined(ARCH_AARCH64)
    adrp    x0, :pg_hi21:egalito_inside_hook_code
    ldr     x1, [x0, #:lo12:egalito_inside_hook_code]
    cbnz    x1, 1f
    mov     x1, #1
    str     x1, [x0, #:lo12:egalito_inside_hook_code]

    stp     x29, x30, [sp, #-0x10]!
    mov     x29, sp
    mov     x0, x30
    adrp    x1, :got:egalito_hook_function_entry_hook
    ldr     x1, [x1, #:got_lo12:egalito_hook_function_entry_hook]
    ldr     x1, [x1]
    blr     x1
    ldp     x29, x30, [sp], #0x10

    adrp    x0, :pg_hi21:egalito_inside_hook_code
    mov     x1, #0
    str     x1, [x0, #:lo12:egalito_inside_hook_code]
1:
    ret
#endif
    .type egalito_hook_function_entry, STT_FUNC
    .size egalito_hook_function_entry, .-egalito_hook_function_entry


    .global egalito_hook_function_exit
egalito_hook_function_exit:
#ifdef ARCH_X86_64
    mov     egalito_inside_hook_code@gotpcrel(%rip), %rax
    cmpb    $0x0, (%rax)
    jne     1f
    push    %rbx
    mov     %rax, %rbx
    movb    $0x1, (%rax)
    mov     0x8(%rsp), %rdi
    mov     egalito_hook_function_exit_hook@gotpcrel(%rip), %rax
    callq   *(%rax)
    movb    $0x0, (%rbx)
    pop     %rbx
1:
    retq
#elif defined(ARCH_AARCH64)
    adrp    x0, :pg_hi21:egalito_inside_hook_code
    ldr     x1, [x0, #:lo12:egalito_inside_hook_code]
    cbnz    x1, 1f
    mov     x1, #1
    str     x1, [x0, #:lo12:egalito_inside_hook_code]

    stp     x29, x30, [sp, #-0x10]!
    mov     x29, sp
    mov     x0, x30
    adrp    x1, :got:egalito_hook_function_exit_hook
    ldr     x1, [x1, #:got_lo12:egalito_hook_function_exit_hook]
    ldr     x1, [x1]
    blr     x1
    ldp     x29, x30, [sp], #0x10

    adrp    x0, :pg_hi21:egalito_inside_hook_code
    mov     x1, #0
    str     x1, [x0, #:lo12:egalito_inside_hook_code]
1:
    ret
#endif
    .type egalito_hook_function_exit, STT_FUNC
    .size egalito_hook_function_exit, .-egalito_hook_function_exit

    .global egalito_hook_instruction
egalito_hook_instruction:
#ifdef ARCH_X86_64
    mov     egalito_inside_hook_code@gotpcrel(%rip), %rax
    cmpb    $0x0, (%rax)
    jne     1f
    push    %rbx
    mov     %rax, %rbx
    movb    $0x1, (%rax)
    mov     0x8(%rsp), %rdi
    mov     egalito_hook_instruction_hook@gotpcrel(%rip), %rax
    callq   *(%rax)
    movb    $0x0, (%rbx)
    pop     %rbx
1:
    retq
#elif defined(ARCH_AARCH64)
    brk     0   /* NYI */
#endif
    .type egalito_hook_instruction, STT_FUNC
    .size egalito_hook_instruction, .-egalito_hook_instruction

   .global egalito_hook_jit_fixup
egalito_hook_jit_fixup:
#ifdef ARCH_X86_64
    # mm1 = gstable offset
    sub     $0x8, %rsp
    push    %rax
    push    %rcx
    push    %rdx
    push    %rsi
    push    %rdi
    push    %r8
    push    %r9
    push    %r10
    push    %r11
#if 1
    # this guards resetting inside egalito_printf
    mov     egalito_inside_hook_code@gotpcrel(%rip), %rax
    cmpb    $0x0, (%rax)
    jne     in_code
    movb    $0x1, (%rax)
#endif

    push    %rbx
    mov     %rax, %rbx

    mov     egalito_jit_gs_fixup@gotpcrel(%rip), %rax
    movq    %mm1, %rdi
    movq    %rdi, 0x50(%rsp)

    callq   *%gs:(%rax)

#if 1
    movb    $0x0, (%rbx)
#endif

    movq    0x50(%rsp), %r11
    movq    %gs:(%r11), %r11
    movq    %r11, 0x50(%rsp)

    pop     %rbx

    pop     %r11
    pop     %r10
    pop     %r9
    pop     %r8
    pop     %rdi
    pop     %rsi
    pop     %rdx
    pop     %rcx
    pop     %rax
    add     $0x8, %rsp
    jmpq    *-0x8(%rsp)

in_code:
    movq    %mm1, %rdi  # offset
    jmp     .
#if 0
    pop     %r12
    pop     %r11
    pop     %r10
    pop     %r9
    pop     %r8
    pop     %rdi
    pop     %rsi
    pop     %rdx
    pop     %rcx
    pop     %rax
    retq
#endif
#elif defined(ARCH_AARCH64)
    brk     0   /* NYI */
#endif
    .type egalito_hook_jit_fixup, STT_FUNC
    .size egalito_hook_jit_fixup, .-egalito_hook_jit_fixup


   .global egalito_hook_jit_reset
egalito_hook_jit_reset:
#ifdef ARCH_X86_64
    mov     egalito_inside_hook_code@gotpcrel(%rip), %rax
    cmpb    $0x0, (%rax)
    jne     1f
    push    %rbx
    mov     %rax, %rbx
    movb    $0x1, (%rax)
    mov     egalito_hook_jit_reset_hook@gotpcrel(%rip), %rax
    callq   *(%rax)
    movb    $0x0, (%rbx)
    pop     %rbx
1:
    retq
#elif defined(ARCH_AARCH64)
    brk     0   /* NYI */
#endif
    .type egalito_hook_jit_reset, STT_FUNC
    .size egalito_hook_jit_reset, .-egalito_hook_jit_reset


//
// begin .bss section
//
    .bss
    .align 8
    .global egalito_inside_hook_code
egalito_inside_hook_code:
    .skip 8
    .type egalito_inside_hook_code, STT_OBJECT
    .size egalito_inside_hook_code, .-egalito_inside_hook_code

    .global egalito_hook_function_entry_hook
    .weak egalito_hook_function_entry_hook
egalito_hook_function_entry_hook:
    .skip 8
    .type egalito_hook_function_entry_hook, STT_OBJECT
    .size egalito_hook_function_entry_hook, .-egalito_hook_function_entry_hook

    .global egalito_hook_function_exit_hook
    .weak egalito_hook_function_exit_hook
egalito_hook_function_exit_hook:
    .skip 8
    .type egalito_hook_function_exit_hook, STT_OBJECT
    .size egalito_hook_function_exit_hook, .-egalito_hook_function_exit_hook

    .global egalito_hook_instruction_hook
    .weak egalito_hook_instruction_hook
egalito_hook_instruction_hook:
    .skip 8
    .type egalito_hook_instruction_hook, STT_OBJECT
    .size egalito_hook_instruction_hook, .-egalito_hook_instruction_hook

    .global egalito_hook_jit_fixup_direct_hook
    .weak egalito_hook_jit_fixup_direct_hook
egalito_hook_jit_fixup_direct_hook:
    .skip 8
    .type egalito_hook_jit_fixup_direct_hook, STT_OBJECT
    .size egalito_hook_jit_fixup_direct_hook, .-egalito_hook_jit_fixup_direct_hook

    .global egalito_hook_jit_fixup_indirect_hook
    .weak egalito_hook_jit_fixup_indirect_hook
egalito_hook_jit_fixup_indirect_hook:
    .skip 8
    .type egalito_hook_jit_fixup_indirect_hook, STT_OBJECT
    .size egalito_hook_jit_fixup_indirect_hook, .-egalito_hook_jit_fixup_indirect_hook

    .global egalito_hook_jit_reset_hook
    .weak egalito_hook_jit_reset_hook
egalito_hook_jit_reset_hook:
    .skip 8
    .type egalito_hook_jit_reset_hook, STT_OBJECT
    .size egalito_hook_jit_reset_hook, .-egalito_hook_jit_reset_hook
