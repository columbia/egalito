#include "resolveplt.h"
#include "operation/find2.h"

void ResolvePLTPass::visit(PLTList *pltList) {
    recurse(pltList);
}

void ResolvePLTPass::visit(PLTTrampoline *pltTrampoline) {
    if(pltTrampoline->getTarget()) return;  // already resolved

    auto symbol = pltTrampoline->getTargetSymbol();
    auto found = ChunkFind2(conductor)
        .findFunction(symbol->getName(), elfSpace);

    if(found) {
        pltTrampoline->setTarget(found);
    }
}
