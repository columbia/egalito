#ifndef EGALITO_SNIPPET_HOOK_H
#define EGALITO_SNIPPET_HOOK_H

#include <assert.h>

#ifdef __cplusplus
extern "C" {
#endif

extern void (*egalito_hook_function_entry_hook)(unsigned long address);
extern void (*egalito_hook_function_exit_hook)(unsigned long address);
extern void (*egalito_hook_instruction_hook)(unsigned long address);

static inline void set_function_entry_hook(void (*f)(unsigned long address)) {
#ifndef ARCH_RISCV
    egalito_hook_function_entry_hook = f;
#else
    assert(0); // no hooking support on RISC-V yet
#endif
}

static inline void set_function_exit_hook(void (*f)(unsigned long address)) {
#ifndef ARCH_RISCV
    egalito_hook_function_exit_hook = f;
#else
    assert(0); // no hooking support on RISC-V yet
#endif
}

static inline void set_instruction_hook(void (*f)(unsigned long address)) {
#ifndef ARCH_RISCV
    egalito_hook_instruction_hook = f;
#else
    assert(0); // no hooking support on RISC-V yet
#endif
}

#ifdef __cplusplus
}
#endif
#endif
