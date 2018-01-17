#include <cstdlib>
#include <vector>
#include <map>
#include "reorderpush.h"
#include "analysis/frametype.h"
#include "analysis/controlflow.h"
#include "analysis/usedef.h"
#include "analysis/reachingdef.h"
#include "chunk/module.h"
#include "chunk/function.h"
#include "chunk/block.h"
#include "instr/instr.h"
#include "chunk/dump.h"
#include "operation/mutator.h"
#include "log/log.h"

void ReorderPush::visit(Module *module) {
    recurse(module);
}

void ReorderPush::visit(Function *function) {
    FrameType frameType(function);
    frameType.dump();

    /*auto prologueEnd = frameType.getSetSPInstr();
    auto epilogueStartList = frameType.getResetSPInstrs();
    if(!prologueEnd || epilogueStartList.empty()) return;*/

#if 0
    ControlFlowGraph cfg(function);
    UDConfiguration config(&cfg);
    UDRegMemWorkingSet working(function, &cfg, true);
    UseDef usedef(&config, &working);

    RegState initialState(nullptr, nullptr);

    /*for(int r = 0; r < X86Register::REGISTER_NUMBER; r ++) {
        initialState.addRegDef(r, new TreeNodeRegister(r));
        working.addToRegSet(r, &initialState);
    }*/

    {
        auto firstBlock = function->getChildren()->getIterable()->get(0);
        int firstBlockID = cfg.getIDFor(firstBlock);
        std::vector<std::vector<int>> order = {{ firstBlockID }};

        usedef.analyze(order);

        std::vector<Instruction *> instrList;
        std::map<Instruction *, std::vector<Instruction *>> dependsMap;

        auto newBlock = new Block();
        bool pastEnd = false;
        Instruction *prev = nullptr;
        for(auto instr : CIter::children(firstBlock)) {
            LOG0(1, "prologue instr: ");
            ChunkDumper dump;
            instr->accept(&dump);

            if(instr == prologueEnd) pastEnd = true;

            if(!pastEnd) {
                auto state = working.getState(instr);
#if 0
                for(auto pair : *state->getRegRefList()) {
                    auto reg = pair.first;
                    auto 
                }
#endif
                state->getRegUseList().dump();
            }
            else {
                instrList.push_back(instr);
                if(prev) dependsMap[instr] = { prev };
            }

            prev = instr;
        }
    }
#elif 0
    {
        auto firstBlock = function->getChildren()->getIterable()->get(0);

        ReachingDef reachingDef(firstBlock);
        reachingDef.analyze();

        reachingDef.dump();
        reachingDef.computeDependencyClosure();

        reachingDef.visitInstructionGroups(
            [this] (const std::vector<Instruction *> &list) {
                return this->pickNextInstruction(list);
            });
    }
#else
    for(auto block : CIter::children(function)) {
        ReachingDef reachingDef(block);
        reachingDef.analyze();

        reachingDef.dump();
        reachingDef.computeDependencyClosure();

        std::vector<Instruction *> newOrder;
        reachingDef.visitInstructionGroups(
            [this, &newOrder] (const std::vector<Instruction *> &list) {
                auto ins = this->pickNextInstruction(list);
                newOrder.push_back(ins);
                return ins;
            });

        ChunkMutator mutator(block);
        mutator.removeLast(block->getChildren()->genericGetSize());
        for(auto ins : newOrder) {
            mutator.append(ins);
        }
    }
#endif
}

Instruction *ReorderPush::pickNextInstruction(
    const std::vector<Instruction *> &list) {

    LOG0(1, "choose between");
    for(auto i : list) {
        LOG0(1, " " << i->getName());
    }
    LOG(1, "");

    auto ins = list[std::rand() % list.size()];
    LOG0(1, "choose order: ");
    ChunkDumper dump;
    ins->accept(&dump);
    return ins;
}
