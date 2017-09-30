#ifdef ARCH_AARCH64
    .text
    .global egalito_log_function
egalito_log_function:
    adrp    x0, :pg_hi21:egalito_inside_log_code
    ldr     x1, [x0, #:lo12:egalito_inside_log_code]
    cbnz    x1, 1f
    mov     x1, #1
    str     x1, [x0, #:lo12:egalito_inside_log_code]

    stp     x29, x30, [sp, #-0x10]!
    mov     x29, sp
    sub     x0, x30, #12
    mov     x1, #1
    bl      egalito_log_function_name
    ldp     x29, x30, [sp], #0x10

    adrp    x0, :pg_hi21:egalito_inside_log_code
    mov     x1, #0
    str     x1, [x0, #:lo12:egalito_inside_log_code]
1:
    ret
    .type egalito_log_function, STT_FUNC
    .size egalito_log_function, .-egalito_log_function

    .global egalito_log_function_ret
egalito_log_function_ret:
    adrp    x0, :pg_hi21:egalito_inside_log_code
    ldr     x1, [x0, #:lo12:egalito_inside_log_code]
    cbnz    x1, 1f
    mov     x1, #1
    str     x1, [x0, #:lo12:egalito_inside_log_code]

    stp     x29, x30, [sp, #-0x10]!
    mov     x29, sp
    add     x0, x30, #4
    mov     x1, #-1
    bl      egalito_log_function_name
    ldp     x29, x30, [sp], #0x10

    adrp    x0, :pg_hi21:egalito_inside_log_code
    mov     x1, #0
    str     x1, [x0, #:lo12:egalito_inside_log_code]
1:
    ret
    .type egalito_log_function_ret, STT_FUNC
    .size egalito_log_function_ret, .-egalito_log_function_ret

    .data
    .global egalito_inside_log_code
egalito_inside_log_code:
    .long 0
    .type egalito_inside_log_code, STT_OBJECT
    .size egalito_inside_log_code, .-egalito_inside_log_code
#endif
