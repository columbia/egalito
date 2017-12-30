#include <cassert>
#include <pthread.h>
#include <cstdlib>
#include "chunk/tls.h"
#include "conductor/setup.h"
#include "conductor/conductor.h"
#include "cminus/print.h"
#include "runtime/managegs.h"

extern ConductorSetup *egalito_conductor_setup;

extern "C" void egalito_jit_gs_transition(ShufflingSandbox *, GSTable *);

extern "C"
int egalito_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
    void *(*start_routine)(void *), void *arg) {

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

    // we need a hook right after the clone syscall, but don't need
    // a wrapper for the original thread start routine.
    int status = pthread_create(thread, attr, start_routine, arg);

    EgalitoTLS::setChild(nullptr);

    // XXX: we need to make sure that the parent does not reset the
    // start_routine until the child has its set of resolver functions

    return status;
}
