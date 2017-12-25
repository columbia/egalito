#include <pthread.h>
#include "cminus/print.h"

int egalito_pthread_create(void *thread, const void *attr,
    void *(*start_routine)(void *), void *arg) {

    egalito_printf("calling egalito_pthread_create\n");
    int status = pthread_create(thread, attr, start_routine, arg);

    return status;
}
