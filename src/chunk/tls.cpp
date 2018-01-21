#include "tls.h"

#ifdef ARCH_X86_64
#define GET_FROM_TLS(name)  \
    __asm__ __volatile__ (  \
        "mov %@:%p1, %0"    \
            : "=r"(name) \
            : "i"(offsetof(EgalitoTLS, name)-sizeof(EgalitoTLS)) \
    );
#define SET_TO_TLS(name)    \
    __asm__ __volatile__ (  \
        "mov %0, %@:%p1"    \
            :   \
            : "r"(name), \
              "i"(offsetof(EgalitoTLS, name)-sizeof(EgalitoTLS)) \
    );
#else
#define GET_FROM_TLS(name)  \
    do { /* NYI */ } while(0)
#define SET_TO_TLS(name)    \
    do { /* NYI */ } while(0)
#endif


ShufflingSandbox *EgalitoTLS::getSandbox() {
    ShufflingSandbox *sandbox = nullptr;
    GET_FROM_TLS(sandbox);
    return sandbox;
}

void EgalitoTLS::setSandbox(ShufflingSandbox *sandbox) {
    SET_TO_TLS(sandbox);
}

GSTable *EgalitoTLS::getGSTable() {
    GSTable *gsTable = nullptr;
    GET_FROM_TLS(gsTable);
    return gsTable;
}

void EgalitoTLS::setGSTable(GSTable *gsTable) {
    SET_TO_TLS(gsTable);
}

EgalitoTLS *EgalitoTLS::getChild() {
    EgalitoTLS *child = nullptr;
    GET_FROM_TLS(child);
    return child;
}

void EgalitoTLS::setChild(EgalitoTLS *child) {
    SET_TO_TLS(child);
}

volatile size_t *EgalitoTLS::getBarrier() {
    volatile size_t *barrier = nullptr;
    GET_FROM_TLS(barrier);
    return barrier;
}

void EgalitoTLS::setBarrier(volatile size_t *barrier) {
    SET_TO_TLS(barrier);
}

void *EgalitoTLS::getJITAddressTable() {
    void *JIT_addressTable = nullptr;
    GET_FROM_TLS(JIT_addressTable);
    return JIT_addressTable;
}

void EgalitoTLS::setJITAddressTable(void *JIT_addressTable) {
    SET_TO_TLS(JIT_addressTable);
}

size_t EgalitoTLS::getJITResetThreshold() {
    size_t JIT_resetThreshold;
    GET_FROM_TLS(JIT_resetThreshold);
    return JIT_resetThreshold;
}

void EgalitoTLS::setJITResetThreshold(size_t JIT_resetThreshold) {
    SET_TO_TLS(JIT_resetThreshold);
}

size_t EgalitoTLS::getJITResetCounter() {
    size_t JIT_resetCounter;
    GET_FROM_TLS(JIT_resetCounter);
    return JIT_resetCounter;
}

void EgalitoTLS::setJITResetCounter(size_t JIT_resetCounter) {
    SET_TO_TLS(JIT_resetCounter);
}

