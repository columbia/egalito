#ifndef EGALITO_PASS_CLEARSPATIAL_H
#define EGALITO_PASS_CLEARSPATIAL_H

#include "chunkpass.h"

class ClearSpatialPass : public ChunkPass {
private:
public:
    virtual void visit(FunctionList *functionList);
    virtual void visit(Function *function);
    virtual void visit(Block *block);
    virtual void visit(DataRegionList *regionList);
    virtual void visit(DataRegion *region);
    virtual void visit(DataSection *section);
};

#endif
