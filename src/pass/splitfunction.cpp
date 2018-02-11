#include <capstone/capstone.h>
#include "splitfunction.h"
#include "analysis/controlflow.h"
#include "analysis/walker.h"
#include "chunk/concrete.h"
#include "instr/semantic.h"
#include "operation/mutator.h"
#include "pass/nonreturn.h"

#include "log/log.h"
#include "log/temp.h"
#include "chunk/dump.h"

void SplitFunction::visit(FunctionList *functionList) {
    NonReturnFunction nonReturnPass;
    do {
        splitPoints.clear();
        recurse(functionList);

        for(auto pair : splitPoints) {
            auto f = pair.first;
            auto b = pair.second;
            ChunkMutator(f).splitFunctionBefore(b);
        }
        if(!splitPoints.empty()) {
            functionList->accept(&nonReturnPass);
        }
    } while(!splitPoints.empty());
}

void SplitFunction::visit(Function *function) {
    if(function->getSymbol()) return;

    //TemporaryLogLevel tll("pass", 10);

    ControlFlowGraph cfg(function);
    Preorder order(&cfg);
    order.genFull(0);

    auto v = order.get();
    if(v.size() > 1) {
        LOG(10, function->getName() << std::hex
            << " at " << function->getAddress()
            << " size " << function->getSize()
            << " might contain " << v.size() << " functions");

        IF_LOG(10) {
            cfg.dumpDot();
            ChunkDumper dump;
            function->accept(&dump);
        }
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

                LOG(10, "   a single nop cannot be a function");
                continue;
            }

            LOG(10, "   split at " << std::hex << block->getAddress());
            splitPoints.emplace_back(function, block);
        }
    }
}

