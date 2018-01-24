#ifdef ARCH_X86_64
    .text
    .global egalito_hook_function_entry
egalito_hook_function_entry:
    movq    %fs:-0x10, %rax
    cmpq    $0x0, %rax
    jne     1f
    push    %rbx
    movq    $0x1, %fs:-0x10
    mov     0x8(%rsp), %rdi
    mov     egalito_hook_function_entry_hook@gotpcrel(%rip), %rax
    callq   *(%rax)
    movq    $0x0, %fs:-0x10
    pop     %rbx
1:
    retq
    .type egalito_hook_function_entry, STT_FUNC
    .size egalito_hook_function_entry, .-egalito_hook_function_entry


    .global egalito_hook_function_exit
egalito_hook_function_exit:
    movq    %fs:-0x10, %rax
    cmpq    $0x0, %rax
    jne     1f
    push    %rbx
    movq    $0x1, %fs:-0x10
    mov     0x8(%rsp), %rdi
    mov     egalito_hook_function_exit_hook@gotpcrel(%rip), %rax
    callq   *(%rax)
    movq    $0x0, %fs:-0x10
    pop     %rbx
1:
    retq
    .type egalito_hook_function_exit, STT_FUNC
    .size egalito_hook_function_exit, .-egalito_hook_function_exit

    .global egalito_hook_instruction
egalito_hook_instruction:
    mov     %fs:-0x10, %rax
    cmpq    $0x0, %rax
    jne     1f
    push    %rbx
    movq    $0x1, %fs:-0x10
    mov     0x8(%rsp), %rdi
    mov     egalito_hook_instruction_hook@gotpcrel(%rip), %rax
    callq   *(%rax)
    movq    $0x0, %fs:-0x10
    pop     %rbx
1:
    retq
    .type egalito_hook_instruction, STT_FUNC
    .size egalito_hook_instruction, .-egalito_hook_instruction

   .global egalito_hook_jit_fixup
egalito_hook_jit_fixup:
    /* mm1 = gstable offset */
    push    %rax
    push    %rcx
    push    %rdx
    push    %rsi
    push    %rdi
    push    %r8
    push    %r9
    push    %r10
    push    %r11
    /*
     for jump table jumps, we may need to save xmm registes as well
     if so, do the same in egalito_hook_jit_fixup_return
    */

    push    %rsp
    /*
     we can't assume 0x10 alignment of SP for jump table jumps
     it must end with 8 on entry of a function
    */
    test    $0xF, %rsp
    jne     2f
    pop     %r11
    sub     $0x10, %rsp
    mov     %r11, (%rsp)
2:

#if 1
    /* this guards resetting inside egalito_printf */
    mov     %fs:-0x10, %rax
    cmpq    $0x0, %rax
    jne     2f
    movq    $0x1, %fs:-0x10
#endif

    push    %rbx

    mov     egalito_jit_gs_fixup@gotpcrel(%rip), %rax
    movq    %mm1, %rdi
    movq    %rdi, %fs:-0x8

    pushq   $0x0                /* !!! special entry */
    movl    $(1f-egalito_hook_jit_fixup), 0x4(%rsp)
    jmpq    *%gs:(%rax)
1:

#if 1
    movq    $0x0, %fs:-0x10
#endif

    movq    %fs:-0x8, %r11
    movq    %gs:(%r11), %r11
    movq    %r11, %fs:-0x8

    pop     %rbx
    pop     %rsp

    pop     %r11
    pop     %r10
    pop     %r9
    pop     %r8
    pop     %rdi
    pop     %rsi
    pop     %rdx
    pop     %rcx
    pop     %rax
    jmpq    *%fs:-0x8

2:
    movq    %mm1, %rdi  /* offset */
    jmp     .
    .type egalito_hook_jit_fixup, STT_FUNC
    .size egalito_hook_jit_fixup, .-egalito_hook_jit_fixup

    .global egalito_hook_jit_fixup_return
egalito_hook_jit_fixup_return:
    /* we can not clobber even %r11 here, because calling a static tail
     * function would violate the ABI safely */
    mov     %r11, %fs:-0x18
    pop     %r11
1:
    movq    %gs:(%r11d), %r11
    cmpq    %gs:0x0, %r11
    je      2f
    add     -0x4(%rsp), %r11d
    xchg    %fs:-0x18, %r11
    jmpq    *%fs:-0x18
2:
    mov     -0x8(%rsp), %r11
    test    %r11d, %r11d
    jne     3f
    movq    %gs:(%r11d), %r11
    add     -0x4(%rsp), %r11d
    xchg    %fs:-0x18, %r11
    jmpq    *%fs:-0x18
3:
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
    /* this guards resetting inside egalito_printf */
    movq    $0x1, %fs:-0x10
#endif

    push    %rsp
    /*
     we can't assume 0x10 alignment of SP for return (again!)
     because we can reach here from egalito_hook_jit_reset_on_syscall
    */
    test    $0xF, %rsp
    jne     5f
    pop     %r10
    sub     $0x10, %rsp
    mov     %r10, (%rsp)
5:

    push    %rbx

    mov     egalito_jit_gs_fixup@gotpcrel(%rip), %rax
    movl    %r11d, %edi

    pushq   $0x8                # !!! special entry
    movl    $(4f-egalito_hook_jit_fixup_return), 0x4(%rsp)
    jmpq    *%gs:(%rax)
4:
#if 1
    movq    $0x0, %fs:-0x10
#endif

    pop     %rbx
    pop     %rsp

    pop     %r11
    pop     %r10
    pop     %r9
    pop     %r8
    pop     %rdi
    pop     %rsi
    pop     %rdx
    pop     %rcx
    pop     %rax

    movq    %r11, -0x8(%rsp)
    jmp     1b
    .type egalito_hook_jit_fixup_return, STT_FUNC
    .size egalito_hook_jit_fixup_return, .-egalito_hook_jit_fixup_return

   .global egalito_hook_jit_reset_on_syscall
egalito_hook_jit_reset_on_syscall:
    /*
     ok to clobber rcx & r11 (see AMD64 Linux Kernel Conventions)
    */
    push    %rax
    push    %rdx
    push    %rsi
    push    %rdi
    push    %r8
    push    %r9
    push    %r10

#if 1
    mov     %fs:-0x10, %rax
    cmpq    $0x0, %rax
    jne     2f
    movq    $0x1, %fs:-0x10
#endif

    push    %rsp
    /*
     we can't assume 0x10 alignment of SP for syscall either
     it must end with 8 on entry of a function
    */
    test    $0xF, %rsp
    je      3f
    pop     %r11
    sub     $0x10, %rsp
    mov     %r11, (%rsp)
3:

    pushq   $0x10
    movl    $(1f-egalito_hook_jit_reset_on_syscall), 0x4(%rsp)
    mov     egalito_jit_gs_reset@gotpcrel(%rip), %rax
    jmpq    *%gs:(%rax)

1:
    pop     %rsp
#if 1
    movq    $0x0, %fs:-0x10

2:
#endif
    pop     %r10
    pop     %r9
    pop     %r8
    pop     %rdi
    pop     %rsi
    pop     %rdx
    pop     %rax
    jmpq    *%gs:0x8
    .type egalito_hook_jit_reset_on_syscall, STT_FUNC
    .size egalito_hook_jit_reset_on_syscall, .-egalito_hook_jit_reset_on_syscall

   .global egalito_hook_after_clone_syscall
egalito_hook_after_clone_syscall:
    test    %rax, %rax
    jnz     1f

    //jmp     .
    pushq   %rax
    mov     egalito_jit_gs_setup_thread@gotpcrel(%rip), %rax
    callq   *%rax
    popq    %rax
1:
    retq
    .type egalito_hook_after_clone_syscall, STT_FUNC
    .size egalito_hook_after_clone_syscall, .-egalito_hook_after_clone_syscall

//
// begin .bss section
//
    .bss
    .align 8

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
#endif
