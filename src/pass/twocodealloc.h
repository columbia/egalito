#ifndef EGALITO_PASS_TWOCODE_ALLOC_H
#define EGALITO_PASS_TWOCODE_ALLOC_H

#include <vector>
#include "chunkpass.h"

class GSTable;
class IFuncList;

class TwocodeAllocPass : public ChunkPass {
private:
    GSTable *gsTable;
    DataSection *gsArray;
    Function *gsAllocFunc;

public:
    TwocodeAllocPass(GSTable *gsTable, DataSection *gsArray)
        : gsTable(gsTable), gsArray(gsArray), gsAllocFunc(nullptr) {}

    virtual void visit(Program *program);
private:
    void createAllocationFunction(Module *module);
};

#endif
