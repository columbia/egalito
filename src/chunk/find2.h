#ifndef EGALITO_CHUNK_FIND2_H
#define EGALITO_CHUNK_FIND2_H

#include "types.h"

class Conductor;
class Function;
class ElfSpace;

class ChunkFind2 {
private:
    Conductor *conductor;
public:
    ChunkFind2(Conductor *conductor) : conductor(conductor) {}

    Function *findFunction(const char *name, ElfSpace *sourceSpace = nullptr);
    Function *findFunctionInSpace(const char *name, ElfSpace *space);

    Function *findFunctionContaining(address_t address);
private:
    Function *findFunctionHelper(const char *name, ElfSpace *space);
    Function *findFunctionContainingHelper(address_t address, ElfSpace *space);
};

#endif
