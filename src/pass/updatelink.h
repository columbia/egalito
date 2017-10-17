#ifndef EGALITO_PASS_UPDATELINK_H
#define EGALITO_PASS_UPDATELINK_H

#include "chunkpass.h"

class Function;

class UpdateLink : public ChunkPass {
private:
    Function *sourceFunction;
public:
    UpdateLink() {}
    virtual void visit(Function *function);
    virtual void visit(Instruction *instruction);
    virtual void visit(DataRegion *dataRegion);
private:
    Link *makeUpdateLink(Link *link, Function *source);
};

#endif
