#include <stdio.h>
#include <ctype.h>

#ifdef ARCH_X86_64
#include <asm/prctl.h>
#include <sys/prctl.h>

extern int arch_prctl(int code, unsigned long *addr);
#endif

int main() {
#ifdef ARCH_X86_64
    unsigned long fs;
    if(arch_prctl(ARCH_GET_FS, &fs) == 0) {
        printf("fs @ 0x%08lx\n", fs);
    }
    else {
        printf("ARCH_GET_FS error\n");
    }
#endif

    printf("'a' should be lowercase: %d\n", islower('a'));
    printf("'A' should not be lowercase: %d\n", islower('A'));
    return 0;
}
