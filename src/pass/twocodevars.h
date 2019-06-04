#ifndef EGALITO_PASS_TWOCODEVARS_H
#define EGALITO_PASS_TWOCODEVARS_H

#include <utility>
#include "chunkpass.h"
#include "chunk/dataregion.h"
#include "chunk/function.h"
#include "chunk/gstable.h"

class TwocodeVarsPass : public ChunkPass {
private:
    GSTable *gsTable;
    Module *otherModule;
public:
    TwocodeVarsPass(GSTable *gsTable, Module *otherModule) : gsTable(gsTable),
        otherModule(otherModule) {}

    virtual void visit(Module *module);
private:
    static void addGSValue(DataSection *section, GSTableEntry *entry);
    static void addVariable(DataSection *section, Chunk *target, const char *suffix);
};

#endif
