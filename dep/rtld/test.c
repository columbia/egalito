#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rtld.h"

extern char _rtld_global[RTLD_GLOBAL_SIZE];
extern char _rtld_global_ro[RTLD_GLOBAL_RO_SIZE];

void print_raw(char *data, size_t size, const char *name) {
    typedef unsigned long element_t;
    const size_t count = sizeof(element_t);

    printf("%s:\n", name);
    for(size_t i = 0; i < size; i += count) {
        printf("0x%-16lx ", *(element_t *)(data + i));
        if((i + count) % (4 * count) == 0) printf("\n");
    }
    printf("\n");
}

void print_assignments1(struct my_rtld_global *s) {
#include "assign1.c"
}

void print_assignments2(struct my_rtld_global_ro *s) {
#include "assign2.c"
}

void info_mode(void) {
    printf("_rtld_global is at %p\n", _rtld_global);
    printf("_rtld_global_ro is at %p\n\n", _rtld_global_ro);

    print_raw(_rtld_global, sizeof(_rtld_global), "_rtld_global");
    print_raw(_rtld_global_ro, sizeof(_rtld_global_ro), "_rtld_global_ro");

    printf("\n// contents of _rtld_global:\n");
    print_assignments1((struct my_rtld_global *)_rtld_global);
    printf("\n// contents of _rtld_global_ro:\n");
    print_assignments2((struct my_rtld_global_ro *)_rtld_global_ro);
}

void generate1(struct my_rtld_global *s) {
#include "generate1.c"
}

void generate2(struct my_rtld_global_ro *s) {
#include "generate2.c"
}

void gen_mode(int id) {
    if(id == 1) generate1((struct my_rtld_global *)_rtld_global);
    if(id == 2) generate2((struct my_rtld_global_ro *)_rtld_global_ro);
}

int main(int argc, char *argv[]) {
    if(sizeof(struct my_rtld_global) != RTLD_GLOBAL_SIZE) {
        puts("struct padding error in definition for rtld_global");
    }
    if(sizeof(struct my_rtld_global_ro) != RTLD_GLOBAL_RO_SIZE) {
        puts("struct padding error in definition for rtld_global_ro");
    }

    if(argc <= 1) {
        info_mode();
        return 0;
    }
    else {
        int id = strtol(argv[1], NULL, 0);
        if(id >= 1 && id <= 2) {
            gen_mode(id);
            return 0;
        }
        else {
            printf("Usage: %s [1|2]\n", argv[0]);
        }
    }
}
