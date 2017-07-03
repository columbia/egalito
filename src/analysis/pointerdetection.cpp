#include <stdint.h>
#include "pointerdetection.h"
#include "analysis/slicingtree.h"
#include "analysis/usedef.h"
#include "analysis/walker.h"
#include "chunk/concrete.h"
#include "instr/isolated.h"
#include "instr/linked-aarch64.h"

#include "log/log.h"

void PointerDetection::detect() {
    UDConfiguration config(1, &cfg);
    UDRegMemWorkingSet working(function, &cfg);
    UseDef usedef(&config, &working);

    cfg.dump();
    cfg.dumpDot();

    SccOrder order(&cfg);
    order.genFull(0);
    usedef.analyze(order.get());

    LOG(5, "");
    LOG(5, "searching for pointers... (checking soundness)");
    for(auto s : working.getStateList()) {
        LOG(5, "state = 0x" << std::hex << s.getInstruction()->getAddress());

        auto semantic = s.getInstruction()->getSemantic();
        if(auto v = dynamic_cast<DisassembledInstruction *>(semantic)) {
            auto assembly = v->getAssembly();
            if(!assembly) continue;
            if(assembly->getId() == ARM64_INS_ADR) {
                detectAtADR(&s);
            }
            else if(assembly->getId() == ARM64_INS_ADRP) {
                detectAtADRP(&s);
            }
        }
    }

    LOG(5, "checking completeness");
    for(auto block : CIter::children(function)) {
        for(auto instr : CIter::children(block)) {
            auto semantic = instr->getSemantic();
            if(dynamic_cast<ControlFlowInstruction *>(semantic)) {
                continue;
            }
            if(auto linked = dynamic_cast<LinkedInstruction *>(semantic)) {
                auto link = linked->getLink();
                if(dynamic_cast<NormalLink *>(link)
                    || dynamic_cast<DataOffsetLink *>(link)) {

                    LOG(5, "link at 0x" << std::hex << instr->getAddress());
                    auto it = found.find(instr);
                    if(it == found.end()) {
                        LOG(1, "MISMATCH: not found: 0x"
                            << std::hex << link->getTargetAddress()
                            << " at 0x" << std::hex << instr->getAddress());
                    }
                    found.erase(instr);
                }
            }
        }
    }
    if(found.size() > 0) {
        for(auto f : found) {
            LOG(1, "MISMATCH: (was not found): 0x" << std::hex << f.second
                << " at 0x" << f.first->getAddress());
        }
    }
}

void PointerDetection::checkLink(Instruction *instruction, address_t target) {
    auto semantic = instruction->getSemantic();
    if(auto linked = dynamic_cast<LinkedInstruction *>(semantic)) {
        if(auto link = dynamic_cast<NormalLink *>(linked->getLink())) {
            LOG(5, "original NORMAL link pointing to : 0x"
                << std::hex << link->getTargetAddress());
            if(link->getTargetAddress() != target) {
                LOG(1, "MISMATCH: 0x" << std::hex << link->getTargetAddress()
                    << " vs 0x" << target
                    << " at 0x" << instruction->getAddress());
            }
        }
        else if(auto link = dynamic_cast<DataOffsetLink *>(linked->getLink())) {
            LOG(5, "original DATA link pointing to : 0x"
                << std::hex << link->getTargetAddress());
            if(link->getTargetAddress() != target) {
                LOG(1, "MISMATCH: 0x" << std::hex << link->getTargetAddress()
                    << " vs 0x" << target
                    << " at 0x" << instruction->getAddress());
            }
        }
    }

}

void PointerDetection::detectAtADR(UDState *state) {
    for(auto& def : state->getRegDefList()) {
        if(auto tree = dynamic_cast<TreeNodeAddress *>(def.second)) {
            auto addr = tree->getValue();
            checkLink(state->getInstruction(), addr);
            found[state->getInstruction()] = addr;
        }
        break;  // there should be only one
    }
}

void PointerDetection::detectAtADRP(UDState *state) {
    //TemporaryLogLevel temp("analysis", 9);
    IF_LOG(5) state->dumpState();

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
                        throw "inconsistent offset value";
                    }
                }
                checkLink(o.first->getInstruction(), page + o.second);
                found[o.first->getInstruction()] = page + o.second;
            }
            if(offsetList.getCount() > 0) {
                checkLink(state->getInstruction(), page + offset);
                found[state->getInstruction()] = page + offset;
            }
        }
        break;  // there should be only one
    }
}

bool PageOffsetList::detectOffset(UDState *state, int reg) {
    LOG(5, "==== detectOffset state 0x" << std::hex
        << state->getInstruction()->getAddress() << " ====");
    IF_LOG(5) state->dumpState();

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
                LOG(5, "0x" << std::hex << state->getInstruction()->getAddress()
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
                LOG(5, "0x" << std::hex << state->getInstruction()->getAddress()
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
                LOG(5, "0x" << std::hex << state->getInstruction()->getAddress()
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
                LOG(5, "mov, recurse with " << std::dec << regDst);
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
