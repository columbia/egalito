#include <stdint.h>
#include "pointerdetection.h"
#include "analysis/slicingtree.h"
#include "analysis/usedef.h"
#include "analysis/walker.h"
#include "chunk/concrete.h"
#include "instr/isolated.h"
#include "instr/linked-aarch64.h"

#include "log/log.h"
#include "log/temp.h"

#ifdef ARCH_AARCH64
void PointerDetection::detect(Function *function, ControlFlowGraph *cfg) {
    UDConfiguration config(cfg);
    UDRegMemWorkingSet working(function, cfg);
    UseDef usedef(&config, &working);

    IF_LOG(10) cfg->dump();
    IF_LOG(10) cfg->dumpDot();

    SccOrder order(cfg);
    order.genFull(0);
    usedef.analyze(order.get());

    detect(&working);
}

void PointerDetection::detect(UDRegMemWorkingSet *working) {
    IF_LOG(10) working->getCFG()->dumpDot();

    for(auto block : CIter::children(working->getFunction())) {
        for(auto instr : CIter::children(block)) {
            auto semantic = instr->getSemantic();
            if(dynamic_cast<LinkedInstruction *>(semantic)) continue;
            if(auto v = dynamic_cast<DisassembledInstruction *>(semantic)) {
                auto link = v->getLink();
                if(link && !dynamic_cast<UnresolvedLink *>(link)) continue;
                auto assembly = v->getAssembly();
                if(!assembly) continue;
                if(assembly->getId() == ARM64_INS_ADR) {
                    detectAtADR(working->getState(instr));
                }
                else if(assembly->getId() == ARM64_INS_ADRP) {
                    detectAtADRP(working->getState(instr));
                }
            }
        }
    }
}

void PointerDetection::detectAtADR(UDState *state) {
    for(auto& def : state->getRegDefList()) {
        if(auto tree = dynamic_cast<TreeNodeAddress *>(def.second)) {
            auto addr = tree->getValue();
            pointerList.emplace_back(state->getInstruction(), addr);
        }
        break;  // there should be only one
    }
}

void PointerDetection::detectAtADRP(UDState *state) {
    IF_LOG(10) state->dumpState();

    for(auto& def : state->getRegDefList()) {
        auto reg = def.first;
        if(auto tree = dynamic_cast<TreeNodeAddress *>(def.second)) {
            auto page = tree->getValue();

            PageOffsetList offsetList;
            offsetList.detectOffset(state, reg);
            int64_t offset = 0;
            for(auto& o : offsetList.getList()) {
                if(offset == 0) {
                    offset = o.second;
                }
                else {
                    if(offset != o.second) {
                        TemporaryLogLevel tll("analysis", 1);
                        LOG(1, "for page " << std::hex << page << " at 0x"
                            << state->getInstruction()->getAddress());
                        for(auto& o2 : offsetList.getList()) {
                            LOG(1, "offset " << o2.second << " at "
                                << o2.first->getInstruction()->getAddress());
                        }
                        throw "inconsistent offset value";
                    }
                }
                pointerList.emplace_back(
                    o.first->getInstruction(), page + o.second);
            }
            if(offsetList.getCount() > 0) {
                pointerList.emplace_back(
                    state->getInstruction(), page + offset);
            }
        }
        break;  // there should be only one
    }
}

bool PageOffsetList::detectOffset(UDState *state, int reg) {
    LOG(10, "==== detectOffset state 0x" << std::hex
        << state->getInstruction()->getAddress() << " ====");
    IF_LOG(10) state->dumpState();

    for(auto r : seen[state]) {
        if(r == reg) {
            LOG(5, "  seen already");
            return false;
        }
    }
    seen[state].push_back(reg);

    bool gFound = false;
    for(auto s : state->getRegUse(reg)) {
        bool found = false;
        found = findInAdd(s, reg);
        if(found) { gFound = true; continue; }

        found = findInLoad(s, reg);
        if(found) { gFound = true; continue; }

        found = findInStore(s, reg);
        if(found) { gFound = true; continue; }

        found = detectOffsetAfterCopy(s, reg);
        if(found) { gFound = true; continue; }

        found = detectOffsetAfterPush(s, reg);
        if(found) { gFound = true; }
    }

    return gFound;
}

bool PageOffsetList::findInAdd(UDState *state, int reg) {
    bool found = false;
    for(auto def : state->getRegDefList()) {
        auto tree = def.second;

        TreeCapture cap;
        if(OffsetAdditionForm::matches(tree, cap)) {
            auto base = dynamic_cast<TreeNodePhysicalRegister *>(cap.get(0));
            if(base->getRegister() == reg && base->getWidth() == 8) {
                auto offset = dynamic_cast<TreeNodeConstant *>(
                    cap.get(1))->getValue();
                LOG(10, "0x" << std::hex << state->getInstruction()->getAddress()
                    << " found addition " << std::dec << offset);
                addToList(state, offset);
                found = true;
                break;
            }
        }
    }
    return found;
}

bool PageOffsetList::findInLoad(UDState *state, int reg) {
    bool found = false;
    for(auto def : state->getRegDefList()) {
        auto tree = def.second;

        TreeCapture cap;
        if(PointerLoadForm::matches(tree, cap)) {
            auto base = dynamic_cast<TreeNodePhysicalRegister *>(cap.get(0));
            if(base->getRegister() == reg) {
                auto offset = dynamic_cast<TreeNodeConstant *>(
                    cap.get(1))->getValue();
                LOG(10, "0x" << std::hex << state->getInstruction()->getAddress()
                    << " found addition in load " << std::dec << offset);
                addToList(state, offset);
                found = true;
                break;
            }
        }
    }
    return found;
}

bool PageOffsetList::findInStore(UDState *state, int reg) {
    bool found = false;
    for(auto mem : state->getMemDefList()) {
        auto tree = mem.second;
        TreeCapture cap;
        if(OffsetAdditionForm::matches(tree, cap)) {
            auto base = dynamic_cast<TreeNodePhysicalRegister *>(cap.get(0));
            if(base->getRegister() == reg) {
                auto offset = dynamic_cast<TreeNodeConstant *>(
                    cap.get(1))->getValue();
                LOG(10, "0x" << std::hex << state->getInstruction()->getAddress()
                    << " found addition in store " << std::dec << offset);
                addToList(state, offset);
                found = true;
                break;
            }
        }
    }
    return found;
}

bool PageOffsetList::detectOffsetAfterCopy(UDState *state, int reg) {
    typedef TreePatternCapture<
        TreePatternTerminal<TreeNodePhysicalRegister>
    > CopyForm;

    for(auto def : state->getRegDefList()) {
        auto tree = def.second;

        TreeCapture cap;
        if(CopyForm::matches(tree, cap)) {
            auto regSrc = dynamic_cast<TreeNodePhysicalRegister *>(
                cap.get(0))->getRegister();
            if(regSrc == reg) {
                auto regDst = def.first;
                LOG(10, "MOV, recurse with " << std::dec << regDst);
                return detectOffset(state, regDst);
            }
        }
    }
    return false;
}

bool PageOffsetList::detectOffsetAfterPush(UDState *state, int reg) {
    typedef TreePatternUnary<TreeNodeDereference,
        TreePatternCapture<TreePatternAny>
    > DerefForm;

    bool found = false;
    if(auto memTree = state->getMemDef(reg)) {
        MemLocation store(memTree);
        for(auto loadState : state->getMemUse(reg)) {
            for(auto def : loadState->getRegDefList()) {
                auto tree = def.second;

                TreeCapture cap;
                if(DerefForm::matches(tree, cap)) {
                    MemLocation load(cap.get(0));
                    if(store == load) {
                        found = detectOffset(loadState, def.first);
                        break;
                    }
                }
            }
        }
    }
    return found;
}
#endif
