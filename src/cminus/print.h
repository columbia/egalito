#ifndef EGALITO_CMINUS_PRINT_H
#define EGALITO_CMINUS_PRINT_H

#include <stdarg.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NAME(x) egalito_ ## x
#define egalito_stdout STDOUT_FILENO
#define egalito_stderr STDERR_FILENO

int NAME(printf) (const char *format, ...)
#ifdef __GNUC__
    __attribute__(( format(printf, 1, 2) ))
#endif
    ;
int NAME(fprintf) (int stream, const char *format, ...);
int NAME(vfprintf) (int stream, const char *format, va_list args);

int NAME(sprintf) (char *s, const char *format, ...)
#ifdef __GNUC__
    __attribute__(( format(printf, 2, 3) ))
#endif
    ;
int NAME(snprintf) (char *s, size_t size, const char *format, ...)
#ifdef __GNUC__
    __attribute__(( format(printf, 3, 4) ))
#endif
    ;
int NAME(vsnprintf) (char *s, size_t size, const char *format, va_list args);

int NAME(puts) (const char *s);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif
