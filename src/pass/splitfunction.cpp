#include "splitfunction.h"
#include "analysis/controlflow.h"
#include "analysis/walker.h"
#include "chunk/concrete.h"
#include "operation/mutator.h"

#include "log/log.h"

void SplitFunction::visit(Function *function) {
    if(function->getSymbol()) return;

    ControlFlowGraph cfg(function);
    Preorder order(&cfg);
    order.genFull(0);

    auto v = order.get();
    if(v.size() > 1) {
        LOG(10, function->getName()
            << " might contain " << v.size() << " functions");
        for(size_t i = v.size() - 1; i > 0; --i) {
            auto block = cfg.get(v[i][0])->getBlock();
            LOG(10, "   split at " << std::hex << block->getAddress());
            ChunkMutator(function).splitFunctionBefore(block);
        }
    }
}
