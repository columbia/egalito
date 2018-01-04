#include <stddef.h>
#include "config.h"

#ifndef HAVE_EXPLICIT_BZERO
void explicit_bzero(void *s, size_t n) {
    volatile char *p = s;
    while(n--) *p++ = 0;
}
#endif
