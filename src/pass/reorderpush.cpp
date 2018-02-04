#include <cassert>
#include <cstdlib>
#include <vector>
#include <map>
#include "reorderpush.h"
#include "analysis/frametype.h"
#include "analysis/reachingdef.h"
#include "chunk/module.h"
#include "chunk/function.h"
#include "chunk/block.h"
#include "instr/instr.h"
#include "chunk/dump.h"
#include "operation/mutator.h"

#undef DEBUG_GROUP
#define DEBUG_GROUP dreorder
#include "log/log.h"
#include "log/temp.h"

void ReorderPush::visit(Module *module) {
#ifdef ARCH_X86_64
    if(module->getLibrary()->getRole() != Library::ROLE_MAIN) return;

    recurse(module);
#endif
}

void ReorderPush::visit(Function *function) {
#ifdef ARCH_X86_64
    LOG(1, "ReorderPush for [" << function->getName());

    FrameType frameType(function);
    //frameType.dump();

    auto prologueEnd = frameType.getSetSPInstr();
    auto epilogueStartList = frameType.getResetSPInstrs();
    bool reorderPushes = (prologueEnd && !epilogueStartList.empty());

#if 1  // enable this for super-conservative mode
    reorderPushes = false;
#endif

    std::vector<int> realPushOrder;
    for(auto block : CIter::children(function)) {
        bool allowPushReorder = false;
        bool enforcePopOrder = false;
        if(reorderPushes) {
            allowPushReorder = (prologueEnd->getParent() == block);
            for(auto epilogue : epilogueStartList) {
                if(epilogue->getParent() == block) {
                    enforcePopOrder = true;
                    break;
                }
            }
        }
        if(allowPushReorder && enforcePopOrder) {
            allowPushReorder = false;
            enforcePopOrder = false;
        }

        LOG(1, "ReorderPush for block " << block->getName() << ", push="
            << (allowPushReorder ? 'y' : 'n') << ", pop="
            << (enforcePopOrder ? 'y' : 'n'));

        ReachingDef reachingDef(block);
        reachingDef.analyze();

        reachingDef.dump();
        reachingDef.computeDependencyClosure(
            allowPushReorder || enforcePopOrder);

        if(enforcePopOrder) pushOrder = realPushOrder;

        std::vector<InstructionSemantic *> newOrder;
        reachingDef.visitInstructionGroups(
            [this, &newOrder, allowPushReorder, enforcePopOrder]
                (const std::vector<Instruction *> &list) {

                auto ins = this->pickNextInstruction(list,
                    allowPushReorder, enforcePopOrder);
                newOrder.push_back(ins->getSemantic());
                return ins;
            });

        if(allowPushReorder) realPushOrder = pushOrder;

        ChunkMutator mutator(block, true);
        size_t n = 0;
        for(auto s : newOrder) {
            auto ins = block->getChildren()->getIterable()->get(n);
            n++;
            auto old = ins->getSemantic();
            if(s != old) {
                ins->setSemantic(s);
                if(auto linked = dynamic_cast<LinkedInstruction *>(s)) {
                    linked->setInstruction(ins);
                }
                mutator.modifiedChildSize(ins, old->getSize() - s->getSize());
            }
        }
    }
    pushOrder.clear();
#endif
}

Instruction *ReorderPush::pickNextInstruction(std::vector<Instruction *> list,
    bool recordPushes, bool enforcePops) {

#ifdef ARCH_X86_64
    Instruction *ordainedPop = nullptr;
    if(enforcePops) {
        for(size_t index = 0; index < list.size(); ) {
            auto i = list[index];
            auto popAsm = i->getSemantic()->getAssembly();
            if(popAsm && popAsm->getId() == X86_INS_POP
                && popAsm->getAsmOperands()->getMode() == AssemblyOperands::MODE_REG) {

                auto reg = popAsm->getAsmOperands()->getOperands()[0].reg;
                if(reg == pushOrder.back()) {
                    ordainedPop = i;
                }
                else {
                    list.erase(list.begin() + index);
                    continue;
                }
            }
            index ++;
        }
        assert(!list.empty());
    }

    IF_LOG(1) {
        LOG0(1, "choose between");
        for(auto i : list) {
            LOG0(1, " " << i->getName());
        }
        LOG(1, "");
    }

    auto ins = list[std::rand() % list.size()];
    IF_LOG(1) {
        LOG0(1, "choose order: ");
        ChunkDumper dump;
        ins->accept(&dump);
    }

    auto pushAsm = ins->getSemantic()->getAssembly();
    if(recordPushes && pushAsm && pushAsm->getId() == X86_INS_PUSH
        && pushAsm->getAsmOperands()->getMode() == AssemblyOperands::MODE_REG) {

        pushOrder.push_back(pushAsm->getAsmOperands()->getOperands()[0].reg);
    }

    if(ins == ordainedPop) {
        pushOrder.pop_back();
    }

    return ins;
#else
    return nullptr;
#endif
}
