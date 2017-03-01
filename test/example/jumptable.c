#include <stdio.h>

int main(int argc, char **argv) {
	int x = 0;
	switch(argc) {
	case 1:
		x += 37; break;
	case 2:
		x += 47; break;
	case 4:
		printf("%d\n", x);
		x += 67; break;
	case 5:
		x += 17; break;
	case 6:
		printf("%d\n", x);
		x += 27; break;
	case 16:
		printf("%d\n", x);
		x += 273; break;
	case 26:
		x += 272; break;
	case 36:
		printf("%d\n", x);
		x += 271; break;
	}
	printf("%d\n", x);
	return 0;
}
