#include <assert.h>
#include <pthread.h>
#include <stdlib.h>
#include "cminus/print.h"

struct egalito_thread_arg {
    void *(*start_routine)(void *);
    void *arg;
};

void *egalito_thread_start(void *arg) {
    struct egalito_thread_arg *egalito_arg = arg;
    void *(*org_start_routine)(void *) = egalito_arg->start_routine;
    void *org_arg = egalito_arg->arg;
    free(arg);

    // create a sandbox for this thread here

    egalito_printf("calling original start_routine\n");
    return org_start_routine(org_arg);
}

int egalito_pthread_create(void *thread, const void *attr,
    void *(*start_routine)(void *), void *arg) {

    struct egalito_thread_arg *egalito_arg
        = malloc(sizeof(struct egalito_thread_arg));
    assert(egalito_arg);
    egalito_arg->start_routine = start_routine;
    egalito_arg->arg = arg;

    egalito_printf("hijacking to egalito_pthread_create\n");
    int status = pthread_create(thread, attr,
        egalito_thread_start, egalito_arg);

    return status;
}
