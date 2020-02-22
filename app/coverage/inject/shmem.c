#include <sys/shm.h>
#include <sys/mman.h>
#include "calls.h"

#define EGALITO_MAP_BASE 0x50000000
//#define NULL (void *)0

int strncmp(const char *one, const char *two, size_t n) {
    while(*one && *one == *two && n) one++, two++, n--;
    
    if(n == 0) return 0;
    if(*one < *two) return -1;
    if(*one > *two) return +1;
    return 0;
}

long strtol(const char *nptr, char **endptr, int base) {
    // we cheat and assume base==10
    long value = 0;
    const char *p = nptr;
    while(*p && (*p >= '0' || *p <= '9')) {
        value *= 10;
        value += *p - '0';
        p ++;
    }
    if(p > nptr && endptr) {
        *endptr = (char *)p;
    }
    return value;
}

static void write_string(int stream, const char *message) {
    //if(!message) message = "(null)";

    size_t length = 0;
    while(message[length]) length ++;
    
    write(stream, message, length);
}

void map_shmem(char *env) {
    while(*env) {
        if(strncmp(env, "__AFL_SHM_ID", 12) == 0) {
            write_string(stdout, "Parsing ");
            write_string(stdout, env);
            write_string(stdout, "\n");
            int id = strtol(env + 12 + 1, NULL, 10);
            //printf("shmid=[%d]\n", id);
            void *shm = shmat(id, (void *)EGALITO_MAP_BASE, SHM_RND);
            if (shm == (void *)-1) {
                exit(-1);
            }
            // done!
            write_string(stdout, "Map successful!\n");
            *(unsigned long *)shm = 0xdeadbeef;
            return;
        }
        while(*env++) {}
    }
    write_string(stdout, "Usage: set __AFL_SHM_ID to existing shmem id\n");
    exit(-2);
}

void map_control_page(void) {
    __mmap((void *)(EGALITO_MAP_BASE - 0x1000), 0x1000,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
}

char *find_env(int argc, char **argv) {
    char *env = *(argv + argc + 1);
    while(*env++) {}
    return env;
}

void egalito_allocate_afl_shm(void *__main, int argc, char **argv) {
    //map_shmem(*envp);
    char *p = find_env(argc, argv);
    //if(p != *envp) return 5;
    map_shmem(p);
    map_control_page();
    //exit(0);
}
