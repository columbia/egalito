#ifndef SHUFFLE_CMINUS_CALLS_H
#define SHUFFLE_CMINUS_CALLS_H

#include <unistd.h>  /* for size_t, ssize_t */

void exit(int status);
void *shmat(int shmid, const void *shmaddr, int shmflg);
int shmdt(const void *shmaddr);
ssize_t write(int fd, const void *buf, size_t count);
void *__mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);

#define stdout 1
#define stderr 2

#endif
