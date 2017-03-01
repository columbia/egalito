#include <stdio.h>

void f() {}

int main() {
	void (*p)() = f;
	p();
	return 0;
}
