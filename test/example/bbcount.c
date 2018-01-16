#include <stdio.h>
static int my_basic_block_counter = 0;
int main() {
    int a, b, c;
    a = 1; 
    b = 2; 
    c = 3;
    if (c == 3) {
       a = 2;
    } else {
       a = 3;
       if (b == 3) {
          c = 1; 
       } else {
          c = 2;
       }
    }
    printf("\n\nActual Basic Blocks XXX\nCalculated: %d\n", my_basic_block_counter);
    return 0;
}
