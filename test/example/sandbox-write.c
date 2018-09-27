#include <stdio.h>
#include <unistd.h>

int egalito_sandbox_syscall_1(int fd, const void *buf, size_t count) {
    void* frame = __builtin_frame_address(0);
    unsigned int syscall = *(unsigned int *)((unsigned long)frame + 2*sizeof(unsigned long));
    return count > 10;
}

int egalito_sandbox_syscall_default(int fd, const void *buf, size_t count) {
    void* frame = __builtin_frame_address(0);
    unsigned int syscall = *(unsigned int *)((unsigned long)frame + 2*sizeof(unsigned long));

    // can't use printf
    //printf("[invoking syscall %d]\n", syscall);

    char buffer[128] = "[invoking syscall ";
    size_t len = 18;
    buffer[len++] = (syscall / 100) % 10 + '0';
    buffer[len++] = (syscall / 10) % 10 + '0';
    buffer[len++] = syscall % 10 + '0';
    buffer[len++] = ']';
    buffer[len++] = '\n';
    buffer[len] = 0;
    write(STDOUT_FILENO, buffer, len);

    return 1;  /* allow syscall */
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
