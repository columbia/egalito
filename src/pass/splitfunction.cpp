#include <capstone/capstone.h>
#include "splitfunction.h"
#include "analysis/controlflow.h"
#include "analysis/walker.h"
#include "chunk/concrete.h"
#include "instr/semantic.h"
#include "operation/mutator.h"

#include "log/log.h"

void SplitFunction::visit(FunctionList *functionList) {
    // iterators will be invalidated
    for(size_t i = 0;
        i < functionList->getChildren()->getIterable()->getCount();
        i++) {

        auto function = functionList->getChildren()->getIterable()->get(i);
        visit(function);
    }
}

void SplitFunction::visit(Function *function) {
    if(function->getSymbol()) return;

    ControlFlowGraph cfg(function);
    Preorder order(&cfg);
    order.genFull(0);

    auto v = order.get();
    if(v.size() > 1) {
        LOG(10, function->getName() << std::hex
            << " at " << function->getAddress()
            << " size " << function->getSize()
            << " might contain " << v.size() << " functions");

#if 0
        LOG(10, "orders");
        for(auto o : v) {
            for(auto i : o) {
                LOG0(10, " " << cfg.get(i)->getBlock()->getAddress()
                     << "(" << cfg.get(i)->getBlock()->getSize() << ")");
            }
            LOG(10, "");
        }
#endif

        for(size_t i = v.size() - 1; i > 0; --i) {
            auto block = cfg.get(v[i][0])->getBlock();
            auto instr = static_cast<Instruction *>(
                block->getChildren()->getIterable()->get(0));
            auto semantic = instr->getSemantic();
            if(v[i].size() == 1
               && block->getChildren()->getIterable()->getCount() == 1
               && semantic->getAssembly()->getId() == ARM64_INS_NOP) {

                LOG(10, "   a signle nop can not be a function");
                continue;
            }

            LOG(10, "   split at " << std::hex << block->getAddress());
            ChunkMutator(function).splitFunctionBefore(block);
        }
    }
}

