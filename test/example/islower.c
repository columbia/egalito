#include <stdio.h>
#include <ctype.h>

int main() {
    printf("'a' should be lowercase: %d\n", islower('a'));
    printf("'A' should not be lowercase: %d\n", islower('A'));
    return 0;
}
