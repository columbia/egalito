#include <stdio.h>
#include <unistd.h>

int egalito_sandbox_syscall_1(int fd, const void *buf, size_t count) {
    void* frame = __builtin_frame_address(0);
    unsigned int syscall = *(unsigned int *)((unsigned long)frame - 2*sizeof(unsigned long));
    return count > 10;
}

int main() {
    printf("short 1!\n");
    fflush(stdout);
    printf("Hello World!\n");
    fflush(stdout);
    printf("short 2!\n");
    fflush(stdout);
    return 0;
}
