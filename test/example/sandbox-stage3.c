#include <sys/mman.h>
#include <unistd.h>

int main() {
    void *p = mmap(0, 0x1000, PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    //mprotect(p, 0x1000, PROT_WRITE);
    unsigned int *pp = (unsigned int *)p;
    pp[0] = 0xfa1e0ff3;  // endbr64
    pp[1] = 0xfeeb;      // infinite loop

    mprotect(p, 0x1000, PROT_EXEC);
    void (*ppp)(void) = (void (*)(void))p;
    ppp();
    return 0;
}
