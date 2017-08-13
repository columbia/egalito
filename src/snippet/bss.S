#ifdef ARCH_AARCH64
    .text
    .global egalito_clear_addon_bss
egalito_clear_addon_bss:
    adrp    x0, :got:__bss_start__
    ldr     x1, [x0, #:got_lo12:__bss_start__]
    adrp    x0, :got:__bss_end__
    ldr     x2, [x0, #:got_lo12:__bss_end__]
    sub     x3, x2, x1
    cbz     x3, 2f
1:
    str     xzr, [x1], #8
    sub     x3, x3, #8
    cbnz    x3, 1b
2:
    ret
    .type egalito_clear_addon_bss, STT_FUNC
    .size egalito_clear_addon_bss, .-egalito_clear_addon_bss
#endif
