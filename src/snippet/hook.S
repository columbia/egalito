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
    mov     0x8(%rsp), %rax
    mov     %rax, %rdi
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
    mov     0x8(%rsp), %rax
    mov     %rax, %rdi
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
    mov     0x8(%rsp), %rax
    mov     %rax, %rdi
    mov     egalito_hook_instruction_hook@gotpcrel(%rip), %rax
    callq   *(%rax)
    movb    $0x0, (%rbx)
    pop     %rbx
1:
    retq
#elif defined(ARCH_AARCH64)
    #error NYI
#endif
    .type egalito_hook_instruction, STT_FUNC
    .size egalito_hook_instruction, .-egalito_hook_instruction


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
