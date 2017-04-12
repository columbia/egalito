#include <stdio.h>

int global = 0;
int global2 = 0;
int global3 = 1;
int global4 = 1;
int global5;


int foo() {
	global = 1;
	return 1;
}

int main() {
	puts("Hello, World!");
	return 0;
}
