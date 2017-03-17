#include <stdio.h>
#include <stdbool.h>  // auto-gen code uses bool
#include <string.h>
#include "rtld.h"

void assign1(struct my_rtld_global *s) {
#include "rtld_data1.c"
}

void assign2(struct my_rtld_global_ro *s) {
#include "rtld_data2.c"
}

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

int main() {
    struct my_rtld_global global;
    memset(&global, 0, sizeof(global));
    assign1(&global);
    print_raw((char *)&global, sizeof(global), "rtld_global");

    struct my_rtld_global_ro global_ro;
    memset(&global_ro, 0, sizeof(global_ro));
    assign2(&global_ro);
    print_raw((char *)&global_ro, sizeof(global_ro), "rtld_global_ro");
    return 0;
}
