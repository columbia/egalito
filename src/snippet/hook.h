#ifndef EGALITO_SNIPPET_HOOK_H
#define EGALITO_SNIPPET_HOOK_H

#ifdef __cplusplus
extern "C" {
#endif

extern void (*egalito_hook_function_entry_hook)(unsigned long address);
extern void (*egalito_hook_function_exit_hook)(unsigned long address);
extern void (*egalito_hook_instruction_hook)(unsigned long address);
extern void (*egalito_hook_jit_reset_hook)(void);

static inline void set_function_entry_hook(void (*f)(unsigned long address)) {
    egalito_hook_function_entry_hook = f;
}

static inline void set_function_exit_hook(void (*f)(unsigned long address)) {
    egalito_hook_function_exit_hook = f;
}

static inline void set_instruction_hook(void (*f)(unsigned long address)) {
    egalito_hook_instruction_hook = f;
}

static inline void set_jit_reset_hook(void (*f)(void)) {
    egalito_hook_jit_reset_hook = f;
}

#ifdef __cplusplus
}
#endif
#endif
