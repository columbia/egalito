#define _GNU_SOURCE

#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <stdio.h>
#include <wchar.h>
#include <locale.h>
#include <math.h>

void nop() {}
void breakpoint() {}

// must build with -O0
int main(int argc, char **argv)
{
    uint8_t buf[100];
    uint8_t buf2[100];
    wchar_t wbuf[100];
    wchar_t wbuf2[100];
    double d;

    memset(buf, 0, 10);
    memcpy(buf, buf2, 10);
    __memcpy_chk(buf, buf2, 10, 100);
    mempcpy(buf, buf2, 10);
    memmove(buf, buf2, 10);
    if(memcmp(buf, buf2, 11)) {
        nop();
    }
    if(wmemcmp(wbuf, wbuf2, 11)) {
        nop();
    }
    if(memchr(buf, 0, 0) == NULL) {
        nop();
    }
    if(wmemchr(wbuf, 0, 0) == NULL) {
        nop();
    }
    if(strcmp(buf, buf2)) {
        nop();
    }
    if(strncmp(buf, buf2, 1)) {
        nop();
    }
    if(strcasecmp(buf, buf2)) {
        nop();
    }
    if(strncasecmp(buf, buf2, 1)) {
        nop();
    }
    if(strstr(buf, buf2)) {
        nop();
    }
    if(strlen(argv[0]) > 0) {
        nop();
    }
    if(strnlen(buf, 1) == 0) {
        nop();
    }
    buf[0] = 0;
    buf[1] = 1;
    buf2[0] = 0;
    buf2[1] = 2;
    strcpy(buf, buf2);
    strncpy(buf, buf2, 0);
    stpcpy(buf, buf2);
    stpncpy(buf, buf2, 0);
    if(strchr(buf, 0) == NULL) {
        nop();
    }
    if(strrchr(buf, 0) == NULL) {
        nop();
    }
    if(strchrnul(buf, 0) == NULL) {
        nop();
    }
    if(strspn(buf, buf2) == 0) {
        nop();
    }
    if(strcspn(buf, buf2) == 0) {
        nop();
    }
    if(strpbrk(buf, buf2) == 0) {
        nop();
    }
    {
        locale_t loc = newlocale(1 << LC_ALL, "C", NULL);
        if(strcasecmp_l(buf, buf2, loc) == 0) {
            nop();
        }
    }
    if(strcat(buf2, buf)) {
        nop();
    }

    if(rawmemchr(buf, 0)) {
        nop();
    }
    if(memrchr(buf, 0, 0)) {
        nop();
    }

    wmemset(wbuf, 0, 10);
    if(wcslen(wbuf) == 0) {
        nop();
    }
    if(wcsnlen(wbuf, 1) == 0) {
        nop();
    }
    d = 0.5;
	double z; float zf;
    if(cos(d) > 0.1) nop();
    if(cosf(d) > 0.1) nop();
    if(ceil(d) > 0.1) nop();
    if(ceilf(d) > 0.1) nop();
    if(floor(d) > 0.1) nop();
    if(floorf(d) > 0.1) nop();
    if(trunc(d) > 0.1) nop();
    if(truncf(d) > 0.1) nop();
    if(rint(d) > 0.1) nop();
    if(rintf(d) > 0.1) nop();
    if(tan(d) > 0.1) nop();
    if(tanf(d) > 0.1) nop();
    if(atan(d) > 0.1) nop();
    if(atanf(d) > 0.1) nop();
    sincos(d, &z, &z);
    sincosf(d, &zf, &zf);
    if(sin(d) > 0.1) nop();
    if(sinf(d) > 0.1) nop();
    if(exp(d) > 0.1) nop();
    if(expf(d) > 0.1) nop();
    if(log(d) > 0.1) nop();
    if(logf(d) > 0.1) nop();
    breakpoint();

    return 0;
}
