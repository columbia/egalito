#ifndef EGALITO_PASS_PERMUTEDATA_H
#define EGALITO_PASS_PERMUTEDATA_H

#include "chunk/module.h"
#include "chunkpass.h"

class PermuteDataPass : public ChunkPass {
private:
    // old data section, new data section
    DataSection *ds, *nds;
    // stores map of datavariables (in ds) to dvs (in nds)
    std::map<DataVariable *, DataVariable *> dvmap;
    // stores map of offsets (in ds) to offsets (in nds)
    std::map<address_t, Range> newlayout;
    // set of variables that have to remain in place
    std::map<Range, GlobalVariable *> immobileVariables;
    Module *curModule;
public:
    virtual void visit(Module *module);
    virtual void visit(Instruction *instr);
private:
    Link *updatedLink(Link *link);
private:
    address_t newAddress(address_t address);
    address_t newOffset(address_t offset);
};

#endif
