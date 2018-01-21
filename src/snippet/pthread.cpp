#include <pthread.h>
#include <sys/mman.h>
#include <cstdlib>
#include "chunk/tls.h"
#include "conductor/setup.h"
#include "conductor/conductor.h"
#include "cminus/print.h"
#include "runtime/managegs.h"

extern ConductorSetup *egalito_conductor_setup;

extern "C" void egalito_jit_gs_init(ShufflingSandbox *, GSTable *);

extern "C"
int egalito_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
    void *(*start_routine)(void *), void *arg) {

    auto gsTable = new GSTable(*EgalitoTLS::getGSTable());
    ManageGS::allocateBuffer(gsTable);
    auto sandbox = egalito_conductor_setup->makeShufflingSandbox();

    egalito_jit_gs_init(sandbox, gsTable);

    auto JIT_addressTable = mmap(NULL, JIT_TABLE_SIZE, PROT_READ|PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    auto JIT_resetThreshold = EgalitoTLS::getJITResetThreshold();

    // will be consumed before the child is spawned
    volatile size_t barrier = 0;
    EgalitoTLS child(&barrier, gsTable, sandbox, JIT_addressTable,
        JIT_resetThreshold);

    EgalitoTLS::setChild(&child);

    // we need a hook right after the clone syscall, but don't need
    // a wrapper for the original thread start routine.
    int status = pthread_create(thread, attr, start_routine, arg);

    EgalitoTLS::setChild(nullptr);

    while(!barrier);    // careful: no memory fence here

    return status;
}
