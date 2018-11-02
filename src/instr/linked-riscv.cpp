#include <assert.h>

#include "linked-riscv.h"

#ifdef ARCH_RISCV

void LinkedInstruction::writeTo(char *target, bool useDisp) {
    *reinterpret_cast<uint32_t *>(target) = rebuild();
}

void LinkedInstruction::writeTo(std::string &target, bool useDisp) {
    uint32_t data = rebuild();
    target.append(reinterpret_cast<const char *>(&data), getSize());
}

uint32_t LinkedInstruction::rebuild() {
    assert(0);
    return 0;
}

#endif
