#ifndef EGALITO_INSTR_MEMORY_H
#define EGALITO_INSTR_MEMORY_H
#include "register.h"

class Memory {
private:
    Register base;
    Register index;
    unsigned long displacement;
public:
    Memory(Register base, Register index, unsigned long displacement)
        : base(base), index(index), displacement(displacement) {}
    Register getBase() const { return base; }
    Register getIndex() const { return index; }
    unsigned long getDisplacement() const { return displacement; }
};

#endif
