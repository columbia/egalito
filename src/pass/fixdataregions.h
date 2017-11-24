#ifndef EGALITO_PASS_FIX_DATA_REGIONS_H
#define EGALITO_PASS_FIX_DATA_REGIONS_H

#include "chunkpass.h"

class DataVariable;

class FixDataRegionsPass : public ChunkPass {
private:
    Program *program;
    Module *module;
public:
    virtual void visit(Program *program);
    virtual void visit(Module *module);
    virtual void visit(DataRegionList *dataRegionList);
    virtual void visit(DataRegion *dataRegion);
private:
    bool isForIFuncJumpSlot(DataVariable *var);
};

#endif
