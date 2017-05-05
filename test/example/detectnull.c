#include <stdio.h>

int f();
int main();

int f() {
    printf("%lx %lx\n", f, main);
    return 11;
}
int main() {
    int (*p)() = 0;//f;
    return p();
}
