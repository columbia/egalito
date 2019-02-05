#ifndef EGALITO_PASS_PERMUTEDATA_H
#define EGALITO_PASS_PERMUTEDATA_H

#include "chunk/module.h"
#include "chunkpass.h"

class PermuteDataPass : public ChunkPass {
private:
    std::map<DataVariable *, DataVariable *> dvmap;
    DataSection *ds, *nds;
public:
    virtual void visit(Module *module);
    virtual void visit(Instruction *instr);
private:
    Link *updatedLink(Link *link);
};

#endif
