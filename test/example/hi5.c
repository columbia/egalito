#include <unistd.h>
#include <sys/syscall.h>

void my_write(int, const char *, size_t);
void my_exit(int);

void _start() {
    const char *message = "XXHello, World!\n"+2;
    int length = 0;
    while(message[length]) length ++;

    //syscall(SYS_write, STDOUT_FILENO, message, length);
    my_write(STDOUT_FILENO, message, length);
    my_exit(-1);
}
