#include <stdio.h>
#include <stdlib.h>

#if 0
unsigned long my_basic_block_counter;

void print_block_count() {
    printf("basic block count: %ld\n", my_basic_block_counter);
}

__attribute__ (( __constructor__ ))
void register_callback() {
    atexit(print_block_count);
}
#endif

//unsigned int my_basic_block_counter[3]  = { 0x330A, 0x330B, 0x330C}; // .data
int VAR4[3]  = { 0x440A, 0x440B, 0x440C}; // .data

int main() {
    const char * m = "Hello, world!";
    printf("%s\n", m);
    int a, b, c;
    a = 1; 
    b = 2; 
    c = 3;
    if (c == 3) {
       a = 2;
      VAR4[1]++;
    } else {
       a = 3;
      VAR4[1]++;
       if (b == 3) {
          c = 1; 
          VAR4[1]++;
       } else {
          c = 2;
          VAR4[1]++;
       }
    }
#if 0
    printf("\n\nActual Basic Blocks XXX\nCalculated: %ld\n", my_basic_block_counter);
#endif
    return 0;
}
