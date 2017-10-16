#ifndef EGALITO_SNIPPET_HOOK_H
#define EGALITO_SNIPPET_HOOK_H

#ifdef __cplusplus
extern "C" {
#endif

extern void (*egalito_hook_function_entry_hook)(unsigned long address);
extern void (*egalito_hook_function_exit_hook)(unsigned long address);
extern void (*egalito_hook_jit_fixup_hook)(unsigned long address);

static inline void set_function_entry_hook(void (*f)(unsigned long address)) {
    egalito_hook_function_entry_hook = f;
}

static inline void set_function_exit_hook(void (*f)(unsigned long address)) {
    egalito_hook_function_exit_hook = f;
}

static inline void set_jit_fixup_hook(void (*f)(unsigned long address)) {
    egalito_hook_jit_fixup_hook = f;
}

#ifdef __cplusplus
}
#endif
#endif
