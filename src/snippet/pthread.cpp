#include <cassert>
#include <pthread.h>
#include <cstdlib>
#include "chunk/tls.h"
#include "conductor/setup.h"
#include "conductor/conductor.h"
#include "cminus/print.h"
#include "runtime/managegs.h"

extern ConductorSetup *egalito_conductor_setup;

struct egalito_thread_arg {
    void *(*start_routine)(void *);
    void *arg;
};

extern "C" void egalito_jit_gs_transition(ShufflingSandbox *, GSTable *);

extern "C"
void *egalito_thread_start(void *arg) {
    struct egalito_thread_arg *egalito_arg = (struct egalito_thread_arg *)arg;
    void *(*org_start_routine)(void *) = egalito_arg->start_routine;
    void *org_arg = egalito_arg->arg;
    free(arg);

    egalito_printf("calling original start_routine\n");
    return org_start_routine(org_arg);
}

extern "C"
int egalito_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
    void *(*start_routine)(void *), void *arg) {

    struct egalito_thread_arg *egalito_arg = (struct egalito_thread_arg *)
        malloc(sizeof(struct egalito_thread_arg));

    assert(egalito_arg);
    egalito_arg->start_routine = start_routine;
    egalito_arg->arg = arg;

    // do most of the preparation in the parent context to minimize the time
    // the child thread executes in the parent code space.
    auto gsTable = new GSTable(*EgalitoTLS::getGSTable());
    ManageGS::allocateBuffer(gsTable);
    auto sandbox = egalito_conductor_setup->makeShufflingSandbox();

    egalito_jit_gs_transition(sandbox, gsTable);

    // will be consumed before the child is spawned
    EgalitoTLS child(gsTable, sandbox);
    EgalitoTLS::setChild(&child);

    //egalito_printf("hijacking to egalito_pthread_create\n");
    int status = pthread_create(thread, attr,
        egalito_thread_start, egalito_arg);

    EgalitoTLS::setChild(nullptr);

    // we need to make sure that the parent does not reset the
    // start_routine until the child has its set of resolver functions

    return status;
}
