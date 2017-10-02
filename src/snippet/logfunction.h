#ifndef EGALITO_SNIPPET_LOGFUNCTION_H
#define EGALITO_SNIPPET_LOGFUNCTION_H

#ifdef __cplusplus
extern "C" {
#endif

extern void egalito_log_function_entry(unsigned long address);
extern void egalito_log_function_exit(unsigned long address);

#ifdef __cplusplus
}
#endif

#endif
