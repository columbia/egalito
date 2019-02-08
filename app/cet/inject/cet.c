#define _GNU_SOURCE
#include <asm/prctl.h>
#include <sys/prctl.h>
#include <sys/mman.h>
#include <unistd.h>

#define SHADOW_STACK_SIZE (12*1024*1024)

int arch_prctl(int code, void *addr);

void egalito_allocate_shadow_stack_gs(void) {
    void *memory = mmap(0,
        SHADOW_STACK_SIZE,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

    // layout:
    //   [0] = ptr
    //   [1] = null
    //   [2] = top of stack
    unsigned long *data = memory;
    data[0] = 2*sizeof(unsigned long);

    arch_prctl(ARCH_SET_GS, memory);
}

void egalito_allocate_shadow_stack_const(void) {
    int dummyStackVar = 0xdeadbeef;
    void *dummyStackAddr = (void *)((((unsigned long)&dummyStackVar) 
        & ~0xfff) - 0x1000 + 0xb00000); 
    void *memory = mmap(dummyStackAddr,
        SHADOW_STACK_SIZE,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
    *(char *)memory = 0;
}
