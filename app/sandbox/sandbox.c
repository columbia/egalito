#define _GNU_SOURCE
#include <asm/prctl.h>
#include <sys/prctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/syscall.h>

#define PERM_SIZE 119221
unsigned char perm[PERM_SIZE];

int arch_prctl(int code, void *addr);

__attribute__ (( __constructor__ ))
void allocate_perm(void) {
    arch_prctl(ARCH_SET_GS, 0);
    void *memory = mmap(0, PERM_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    arch_prctl(ARCH_SET_GS, memory);
}

unsigned char *get_perm() {
    unsigned long p;
    arch_prctl(ARCH_GET_GS, &p);
    return (unsigned char *)p;
}

// mmap
int egalito_sandbox_syscall_9(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    void* frame = __builtin_frame_address(0);
    unsigned long *syscallNum = (unsigned long *)((unsigned long)frame + 2*sizeof(unsigned long));
    unsigned char *perm = get_perm();
    if(!perm) return 1;  // no perm array yet, must be in constructor

    unsigned long addr2 = (unsigned long)syscall((int)*syscallNum, addr, length, prot, flags, fd, offset);  // mmap
    *syscallNum = addr2;
    for (size_t i = 0; i < length; i += 0x1000) {
        unsigned long address = (unsigned long)addr2 + i;
        if ((perm[address % PERM_SIZE] & PROT_WRITE) && (prot & PROT_EXEC)) {
            syscall(60, 10);  // exit
            //return 0;
        }
        perm[address % PERM_SIZE] |= (unsigned char)prot;
    }
    return 0;
}

// mprotect
int egalito_sandbox_syscall_10(void *addr, size_t len, int prot) {
    void* frame = __builtin_frame_address(0);
    unsigned int syscallNum = *(unsigned int *)((unsigned long)frame + 2*sizeof(unsigned long));
    unsigned char *perm = get_perm();
    if(!perm) return 1;  // no perm array yet???

    for (size_t i = 0; i < len; i += 0x1000) {
        unsigned long address = (unsigned long)addr + i;
        if ((perm[address % PERM_SIZE] & PROT_WRITE) && (prot & PROT_EXEC)) {
            syscall(60, 10);  // exit
            //return 0;
        }
        perm[address % PERM_SIZE] |= (unsigned char)prot;
    }
    return 1;
}

// munmap
int egalito_sandbox_syscall_11(void *addr, size_t len) {
    void* frame = __builtin_frame_address(0);
    unsigned int syscallNum = *(unsigned int *)((unsigned long)frame + 2*sizeof(unsigned long));
    unsigned char *perm = get_perm();
    if(!perm) return 1;  // no perm array yet???

    for (size_t i = 0; i < len; i += 0x1000) {
        unsigned long address = (unsigned long)addr + i;
        perm[address % PERM_SIZE] = 0;
    }
    return 1;
}
