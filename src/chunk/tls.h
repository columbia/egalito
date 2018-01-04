#ifndef EGALITO_ELF_TLS_H
#define EGALITO_ELF_TLS_H
#include <cstddef>
#include "transform/sandbox.h"

/*
 * How glibc handles TLS for AARCH64:
 *
 * For static binary,
 *  - struct pthread for main is in the heap (by __sbrk).
 *  - DTV is statically allocated in data section.
 *  - tpidr_el0 points to the end of the struct pthread
 *    where the pointer to DTV and private is allocated (i.e. TLS_DTV_AT_TP).
 *
 * When a pthread is created, similar structures are allocated on stack.
 *  - it has to copy original .tdata & .tbss (at load time or when
 *    referenced (i.e. __tls_get_addr() is called)).
 *  - it has to provide its address through __tls_get_addr().
 */


// We directly reserve areas as a substitute for TLS in libegalito
// since using a thread local storage in libegalito requires a heavy
// operation for libegalito (e.g. __tls_get_addr)

class GSTable;

// the list grows upward
class EgalitoTLS {
private:
    size_t reserve;
    volatile size_t *barrier;
    EgalitoTLS *child;  // used only to initialize the child's TLS
    GSTable *gsTable;
    ShufflingSandbox *sandbox;
    void *JIT_addressTable;
    size_t JIT_jitting;     // hard coded in assembly (-0x10)
    size_t JIT_temporary;   // hard coded in assembly (-0x8)
public:
    EgalitoTLS(volatile size_t *barrier, GSTable *gsTable,
        ShufflingSandbox *sandbox, void *JIT_addressTable)
        : reserve(0),
        barrier(barrier), child(nullptr), gsTable(gsTable), sandbox(sandbox),
        JIT_addressTable(JIT_addressTable), JIT_jitting(0) {}

    static ShufflingSandbox *getSandbox();
    static void setSandbox(ShufflingSandbox *sandbox);
    static GSTable *getGSTable();
    static void setGSTable(GSTable *gsTable);
    static EgalitoTLS *getChild();
    static void setChild(EgalitoTLS *child);
    static volatile size_t *getBarrier();
    static void setBarrier(volatile size_t *barrier);
    static void *getJITAddressTable();
    static void setJITAddressTable(void *JIT_addressTable);
};

#endif
