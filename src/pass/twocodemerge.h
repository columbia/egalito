#ifndef EGALITO_PASS_TWOCODEMERGE_H
#define EGALITO_PASS_TWOCODEMERGE_H

#include <utility>
#include "chunkpass.h"
#include "chunk/dataregion.h"
#include "chunk/function.h"
#include "chunk/gstable.h"

class TwocodeMergePass : public ChunkPass {
private:
    Module *otherModule;
    std::vector<Function *> transformed;
public:
    TwocodeMergePass(Module *otherModule) : otherModule(otherModule) {}

    virtual void visit(Module *module);
    void copyFunctionsTo(Module *module);
private:
};

#endif
