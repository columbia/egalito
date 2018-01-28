#define _GNU_SOURCE

#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <stdio.h>
#include <wchar.h>
#include <locale.h>

void nop() {}
void breakpoint() {}

// must build with -O0
int main(int argc, char **argv)
{
    uint8_t buf[100];
    uint8_t buf2[100];
    wchar_t wbuf[100];

    memset(buf, 0, 10);
    memcpy(buf, buf2, 10);
    mempcpy(buf, buf2, 10);
    memmove(buf, buf2, 10);
    if(memcmp(buf, buf2, 11)) {
        nop();
    }
    if(memchr(buf, 0, 0) == NULL) {
        nop();
    }
    if(strcmp(buf, buf2)) {
        nop();
    }
    if(strncmp(buf, buf2, 1)) {
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
    stpcpy(buf, buf2);
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

    wmemset(wbuf, 0, 10);
    if(wcslen(wbuf) == 0) {
        nop();
    }
    if(wcsnlen(wbuf, 1) == 0) {
        nop();
    }

    breakpoint();

    return 0;
}
