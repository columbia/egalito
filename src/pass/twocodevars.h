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
    DataSection *gsSection;
public:
    TwocodeVarsPass(GSTable *gsTable, Module *otherModule) : gsTable(gsTable),
        otherModule(otherModule), gsSection(nullptr) {}

    virtual void visit(Module *module);
    DataSection *getGSSection() const { return gsSection; }
private:
    static void addBaseSymbol(DataSection *section, const char *symbolName);
    static void addGSValue(DataSection *section, GSTableEntry *entry);
    static void addVariable(DataSection *section, Chunk *target, const char *suffix);
};

#endif
