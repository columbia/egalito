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
