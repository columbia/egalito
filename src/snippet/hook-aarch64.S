#ifdef ARCH_AARCH64
    .text
    .global egalito_hook_function_entry
egalito_hook_function_entry:
    adrp    x0, :got:egalito_inside_hook_code
    ldr     x0, [x0, #:got_lo12:egalito_inside_hook_code]
    ldr     x1, [x0]
    cbnz    x1, 1f
    mov     x1, #1
    str     x1, [x0]

    stp     x29, x30, [sp, #-0x10]!
    mov     x29, sp
    mov     x0, x30
    adrp    x1, :got:egalito_hook_function_entry_hook
    ldr     x1, [x1, #:got_lo12:egalito_hook_function_entry_hook]
    ldr     x1, [x1]
    blr     x1
    ldp     x29, x30, [sp], #0x10

    adrp    x0, :got:egalito_inside_hook_code
    ldr     x0, [x0, #:lo12:egalito_inside_hook_code]
    mov     x1, #0
    str     x1, [x0]
1:
    ret
    .type egalito_hook_function_entry, STT_FUNC
    .size egalito_hook_function_entry, .-egalito_hook_function_entry


    .global egalito_hook_function_exit
egalito_hook_function_exit:
    adrp    x0, :got:egalito_inside_hook_code
    ldr     x0, [x0, #:got_lo12:egalito_inside_hook_code]
    ldr     x1, [x0]
    cbnz    x1, 1f
    mov     x1, #1
    str     x1, [x0]

    stp     x29, x30, [sp, #-0x10]!
    mov     x29, sp
    mov     x0, x30
    adrp    x1, :got:egalito_hook_function_exit_hook
    ldr     x1, [x1, #:got_lo12:egalito_hook_function_exit_hook]
    ldr     x1, [x1]
    blr     x1
    ldp     x29, x30, [sp], #0x10

    adrp    x0, :got:egalito_inside_hook_code
    ldr     x0, [x0, #:got_lo12:egalito_inside_hook_code]
    mov     x1, #0
    str     x1, [x0]
1:
    ret
    .type egalito_hook_function_exit, STT_FUNC
    .size egalito_hook_function_exit, .-egalito_hook_function_exit

    .global egalito_hook_instruction
egalito_hook_instruction:
    brk     0   /* NYI */
    .type egalito_hook_instruction, STT_FUNC
    .size egalito_hook_instruction, .-egalito_hook_instruction

   .global egalito_hook_jit_fixup
egalito_hook_jit_fixup:
    brk     0   /* NYI */
    .type egalito_hook_jit_fixup, STT_FUNC
    .size egalito_hook_jit_fixup, .-egalito_hook_jit_fixup

    .global egalito_hook_jit_fixup_return
egalito_hook_jit_fixup_return:
    brk     0   /* NYI */
    .type egalito_hook_jit_fixup_return, STT_FUNC
    .size egalito_hook_jit_fixup_return, .-egalito_hook_jit_fixup_return

   .global egalito_hook_jit_reset_on_syscall
egalito_hook_jit_reset_on_syscall:
    brk     0   /* NYI */
    .type egalito_hook_jit_reset_on_syscall, STT_FUNC
    .size egalito_hook_jit_reset_on_syscall, .-egalito_hook_jit_reset_on_syscall

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
#endif
