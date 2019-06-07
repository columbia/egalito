#ifndef EGALITO_PASS_TWOCODEMERGE_H
#define EGALITO_PASS_TWOCODEMERGE_H

#include <utility>
#include <vector>
#include <set>
#include "chunkpass.h"
#include "chunk/dataregion.h"
#include "chunk/function.h"
#include "chunk/gstable.h"

class TwocodeMergePass : public ChunkPass {
private:
    Module *otherModule;
    std::vector<Function *> transformed;
    std::set<DataRegion *> regionsNeeded;
public:
    TwocodeMergePass(Module *otherModule) : otherModule(otherModule) {}

    virtual void visit(Module *module);
private:
    bool updateLinks(Module *module, Function *otherFunc);

    void copyFunctionsTo(Module *module);
    void copyRegionsTo(Module *module);
};

#endif
