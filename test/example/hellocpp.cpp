#include <stdio.h>
unsigned int my_basic_block_counter[3]  = { 0x330A, 0x330B, 0x330C}; // .data
int VAR4[3]  = { 0x440A, 0x440B, 0x440C}; // .data

int main() {
    char * m = "Hello, world!";
    printf("%s", m);
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
    printf("\n\nActual Basic Blocks XXX\nCalculated: %d", my_basic_block_counter[1]);
    return 0;
}
