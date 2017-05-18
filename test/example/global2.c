#include <stdio.h>

int var_data = 42;
int var_bss;
const int var_rodata = 55;

int main() {
    printf("var_data    = %d\n", var_data);
    printf("var_bss     = %d\n", var_bss);
    printf("var_rodata  = %d\n", var_rodata);
    var_data = 43;
    var_bss = 1;
    printf("var_data    = %d\n", var_data);
    printf("var_bss     = %d\n", var_bss);
    return 0;
}
