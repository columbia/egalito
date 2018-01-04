#include "tls.h"

ShufflingSandbox *EgalitoTLS::getSandbox() {
    ShufflingSandbox *sandbox = nullptr;
#ifdef ARCH_X86_64
    __asm__ __volatile__ (
        "mov %@:%p1, %0"
            : "=r"(sandbox)
            : "i"(offsetof(EgalitoTLS, sandbox)-sizeof(EgalitoTLS))
    );
#endif
    return sandbox;
}

void EgalitoTLS::setSandbox(ShufflingSandbox *sandbox) {
#ifdef ARCH_X86_64
    __asm__ __volatile__ (
        "mov %0, %@:%p1"
            :
            : "r"(sandbox),
              "i"(offsetof(EgalitoTLS, sandbox)-sizeof(EgalitoTLS))
    );
#endif
}

GSTable *EgalitoTLS::getGSTable() {
    GSTable *gsTable = nullptr;
#ifdef ARCH_X86_64
    __asm__ __volatile__ (
        "mov %@:%p1, %0"
            : "=r"(gsTable)
            : "i"(offsetof(EgalitoTLS, gsTable)-sizeof(EgalitoTLS))
    );
#endif
    return gsTable;
}

void EgalitoTLS::setGSTable(GSTable *gsTable) {
#ifdef ARCH_X86_64
    __asm__ __volatile__ (
        "mov %0, %@:%p1"
            :
            : "r"(gsTable),
              "i"(offsetof(EgalitoTLS, gsTable)-sizeof(EgalitoTLS))
    );
#endif
}

EgalitoTLS *EgalitoTLS::getChild() {
    EgalitoTLS *child = nullptr;
#ifdef ARCH_X86_64
    __asm__ __volatile__ (
        "mov %@:%p1, %0"
            : "=r"(child)
            : "i"(offsetof(EgalitoTLS, child)-sizeof(EgalitoTLS))
    );
#endif
    return child;
}

void EgalitoTLS::setChild(EgalitoTLS *child) {
#ifdef ARCH_X86_64
    __asm__ __volatile__ (
        "mov %0, %@:%p1"
            :
            : "r"(child),
              "i"(offsetof(EgalitoTLS, child)-sizeof(EgalitoTLS))
    );
#endif
}

volatile size_t *EgalitoTLS::getBarrier() {
    volatile size_t *barrier = nullptr;
#ifdef ARCH_X86_64
    __asm__ __volatile__ (
        "mov %@:%p1, %0"
            : "=r"(barrier)
            : "i"(offsetof(EgalitoTLS, barrier)-sizeof(EgalitoTLS))
    );
#endif
    return barrier;
}

void EgalitoTLS::setBarrier(volatile size_t *barrier) {
#ifdef ARCH_X86_64
    __asm__ __volatile__ (
        "mov %0, %@:%p1"
            :
            : "r"(barrier),
              "i"(offsetof(EgalitoTLS, barrier)-sizeof(EgalitoTLS))
    );
#endif
}

void *EgalitoTLS::getJITAddressTable() {
    void *JIT_addressTable = nullptr;
#ifdef ARCH_X86_64
    __asm__ __volatile__ (
        "mov %@:%p1, %0"
            : "=r"(JIT_addressTable)
            : "i"(offsetof(EgalitoTLS, JIT_addressTable)-sizeof(EgalitoTLS))
    );
#endif
    return JIT_addressTable;
}

void EgalitoTLS::setJITAddressTable(void *JIT_addressTable) {
#ifdef ARCH_X86_64
    __asm__ __volatile__ (
        "mov %0, %@:%p1"
            :
            : "r"(JIT_addressTable),
              "i"(offsetof(EgalitoTLS, JIT_addressTable)-sizeof(EgalitoTLS))
    );
#endif
}
