#include "tls.h"

ShufflingSandbox *EgalitoTLS::getSandbox() {
    ShufflingSandbox *sandbox;
    __asm__ __volatile__ (
        "mov %@:%p1, %0"
            : "=r"(sandbox)
            : "i"(offsetof(EgalitoTLS, sandbox)-sizeof(EgalitoTLS))
    );
    return sandbox;
}

void EgalitoTLS::setSandbox(ShufflingSandbox *sandbox) {
    __asm__ __volatile__ (
        "mov %0, %@:%p1"
            :
            : "r"(sandbox),
              "i"(offsetof(EgalitoTLS, sandbox)-sizeof(EgalitoTLS))
    );
}

GSTable *EgalitoTLS::getGSTable() {
    GSTable *gsTable;
    __asm__ __volatile__ (
        "mov %@:%p1, %0"
            : "=r"(gsTable)
            : "i"(offsetof(EgalitoTLS, gsTable)-sizeof(EgalitoTLS))
    );
    return gsTable;
}

void EgalitoTLS::setGSTable(GSTable *gsTable) {
    __asm__ __volatile__ (
        "mov %0, %@:%p1"
            :
            : "r"(gsTable),
              "i"(offsetof(EgalitoTLS, gsTable)-sizeof(EgalitoTLS))
    );
}

EgalitoTLS *EgalitoTLS::getChild() {
    EgalitoTLS *child;
    __asm__ __volatile__ (
        "mov %@:%p1, %0"
            : "=r"(child)
            : "i"(offsetof(EgalitoTLS, child)-sizeof(EgalitoTLS))
    );
    return child;
}

void EgalitoTLS::setChild(EgalitoTLS *child) {
    __asm__ __volatile__ (
        "mov %0, %@:%p1"
            :
            : "r"(child),
              "i"(offsetof(EgalitoTLS, child)-sizeof(EgalitoTLS))
    );
}

volatile size_t *EgalitoTLS::getBarrier() {
    volatile size_t *barrier;
    __asm__ __volatile__ (
        "mov %@:%p1, %0"
            : "=r"(barrier)
            : "i"(offsetof(EgalitoTLS, barrier)-sizeof(EgalitoTLS))
    );
    return barrier;
}

void EgalitoTLS::setBarrier(volatile size_t *barrier) {
    __asm__ __volatile__ (
        "mov %0, %@:%p1"
            :
            : "r"(barrier),
              "i"(offsetof(EgalitoTLS, barrier)-sizeof(EgalitoTLS))
    );
}

void *EgalitoTLS::getJITAddressTable() {
    void *JIT_addressTable;
    __asm__ __volatile__ (
        "mov %@:%p1, %0"
            : "=r"(JIT_addressTable)
            : "i"(offsetof(EgalitoTLS, JIT_addressTable)-sizeof(EgalitoTLS))
    );
    return JIT_addressTable;
}

void EgalitoTLS::setJITAddressTable(void *JIT_addressTable) {
    __asm__ __volatile__ (
        "mov %0, %@:%p1"
            :
            : "r"(JIT_addressTable),
              "i"(offsetof(EgalitoTLS, JIT_addressTable)-sizeof(EgalitoTLS))
    );
}
