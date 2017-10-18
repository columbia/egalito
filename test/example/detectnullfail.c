#include <stdio.h>
#include <stdlib.h>

void egalito_null_ptr_check_fail(void) {
    printf("egalito null ptr check failed at 0x%lx\n",
        (unsigned long)__builtin_return_address(0));
    exit(1);
}
