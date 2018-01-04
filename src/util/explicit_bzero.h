#ifndef EGALITO_UTIL_EXPLICIT_BZERO
#define EGALITO_UTIL_EXPLICIT_BZERO

#ifdef __cplusplus
extern "C" {
#endif

#ifndef HAVE_EXPLICIT_BZERO
extern void explicit_bzero(void *s, size_t n);
#endif

#ifdef __cplusplus
}
#endif
#endif
