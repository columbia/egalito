#include "resolveplt.h"
#include "elf/symbol.h"
#include "chunk/program.h"
#include "operation/find2.h"

#include "log/log.h"

void ResolvePLTPass::visit(Module *module) {
    this->module = module;
    recurse(module);
}

void ResolvePLTPass::visit(PLTList *pltList) {
    recurse(pltList);
}

void ResolvePLTPass::visit(PLTTrampoline *pltTrampoline) {
    if(pltTrampoline->getTarget()) return;  // already resolved

    auto symbol = pltTrampoline->getTargetSymbol();
    auto found = ChunkFind2(program)
        .findFunction(symbol->getName(), module);

    if(found) {
        pltTrampoline->setTarget(found);
    }
    else {
        LOG(12, "unresolved pltTrampoline target "
            << symbol->getName() << " unused?");
    }
}
