#include "jumptabledetection.h"
#include "analysis/walker.h"
#include "chunk/concrete.h"
#include "instr/concrete.h"

#include "log/log.h"

void JumptableDetection::detect() {
    if(containsIndirectJump()) {
        UDConfiguration config(1, &cfg);
        UDRegMemWorkingSet working(function, &cfg);
        UseDef usedef(&config, &working);

        cfg.dump();
        cfg.dumpDot();

        SccOrder order(&cfg);
        order.genFull(0);
        usedef.analyze(order.get());

        for(auto block : CIter::children(function)) {
            auto instr = block->getChildren()->getIterable()->getLast();
            auto s = instr->getSemantic();
            if(dynamic_cast<IndirectJumpInstruction *>(s)) {
                detectAt(working.getState(instr));
            }
        }
    }
}

void JumptableDetection::detectAt(UDState *state) {
    checkFlag = false;
    LOG(1, "indirect jump at 0x" << std::hex
        << state->getInstruction()->getAddress());

    auto regRefList = state->getRegRefList();
    auto it = regRefList.cbegin();
    if(it != regRefList.cend()) {   // may not be found if producer was skipped
        auto reg = it->first;
        LOG(1, " reg = " << std::dec << reg);
        for(auto s : it->second) {
            LOG(1, " defined in parent state = 0x" << std::hex
                << s->getInstruction()->getAddress());
            auto def = s->getRegDef(reg);
            if(!def) {
                LOG(1, " definition not found");
                continue;
            }

            LOG0(1, " as: ");
            IF_LOG(1) def->print(TreePrinter(0, 0));
            LOG(1, "");

            TreeCapture cap1, cap2;
            if(MakeJumpTargetForm1::matches(def, cap1)) {
                LOG(1, "matches jump target form1!");
                auto regTree1
                    = dynamic_cast<TreeNodePhysicalRegister *>(cap1.get(0));
                auto regTree2
                    = dynamic_cast<TreeNodePhysicalRegister *>(cap1.get(1));

                if(parseTableBase(s, regTree1->getRegister())) {
                    LOG(1, "index 0: matches table base form");
                    checkFlag =
                        parseTableOffset(s, regTree2->getRegister());
                }
                else if(parseTableBase(s, regTree2->getRegister())) {
                    LOG(1, "index 1: matches table base form");
                    checkFlag =
                        parseTableOffset(s, regTree1->getRegister());
                }
            }
            else if(MakeJumpTargetForm2::matches(def, cap2)) {
                LOG(1, "matches jump target form2!");
                auto regTree1
                    = dynamic_cast<TreeNodePhysicalRegister *>(cap2.get(0));
                auto regTree2
                    = dynamic_cast<TreeNodePhysicalRegister *>(cap2.get(1));

                if(parseTableBase(s, regTree1->getRegister())) {
                    LOG(1, "index 0: matches table base form");
                    checkFlag =
                        parseTableOffset(s, regTree2->getRegister());
                }
            }
            else {
                auto instr = s->getInstruction();
                auto semantic = instr->getSemantic();
                if(auto v = dynamic_cast<DisassembledInstruction *>(semantic)) {
                    if(auto assembly = v->getAssembly()) {
                        if(assembly->getId() == ARM64_INS_ADD) {
                            throw "missed?";
                        }
                    }
                }
            }
        }
    }

    check(state->getInstruction(), checkFlag);
}

void JumptableDetection::check(Instruction *instruction, bool found) const {
    bool wasFound = false;
    auto module = dynamic_cast<Module *>(function->getParent()->getParent());
    if(!module) throw "no module?";

    auto jumptablelist = module->getJumpTableList();
    for(auto jt : CIter::children(jumptablelist)) {
        if(jt->getInstruction() == instruction) {
            wasFound = true;
            break;
        }
    }

    if(found != wasFound) {
        LOG(1, "MISMATCH: " << (found ? "(was not found)" : "(not found)")
            << " 0x" << std::hex << instruction->getAddress());
    }
}

bool JumptableDetection::parseTableBase(UDState *state, int reg) {
    LOG(1, "[TableBase] looking for reference in 0x" << std::hex
        << state->getInstruction()->getAddress()
        << " register " << std::dec << reg);

    if(auto refList = state->getRegRef(reg)) {
        for(auto& s : *refList) {
            if(auto def = s->getRegDef(reg)) {
                IF_LOG(1) def->print(TreePrinter(0, 0)); LOG(1, "");
                if(auto baseTree = dynamic_cast<TreeNodeAddress *>(def)) {
                    LOG(1, "table base form 0x"
                        << std::hex << baseTree->getValue());
                    return true;
                }

                TreeCapture cap1;
                if(MakeBaseAddressForm::matches(def, cap1)) {
                    auto pageRegTree
                        = dynamic_cast<TreeNodePhysicalRegister *>(cap1.get(0));
                    //cap1.get(1) contains offset
                    return parseMakeBase(s, pageRegTree->getRegister());
                }

                TreeCapture cap2;
                if(LoadBaseAddressForm::matches(def, cap2)) {
                    LOG(1, "base address could have been pushed onto stack");
                    //cap2.get(1) contains offset
                    return parseLoadBase(s, reg);
                }
            }
            else {
                LOG(1, " no def in ref target");
            }
        }
    }
    else {
        LOG(1, " no ref");
    }
    return false;
}

bool JumptableDetection::parseLoadBase(UDState *state, int reg) {
    LOG(1, "and loaded back in 0x"
        << std::hex << state->getInstruction()->getAddress()
        << " as register " << std::dec << reg);

    auto deref = dynamic_cast<TreeNodeDereference *>(state->getRegDef(reg));
    if(!deref) return false;

    bool found = false;
    MemLocation loadLoc(deref->getChild());
    if(auto memref = state->getMemRef(reg)) {
        for(auto store : *memref) {
            for(auto it = store->getMemDefList().cbegin();
                it != store->getMemDefList().cend();
                ++it) {
                MemLocation storeLoc(it->second);
                if(loadLoc == storeLoc) {
                    LOG(1, "  stored in 0x" << std::hex
                        << store->getInstruction()->getAddress());

                    found |= parseTableBase(store, it->first);
                }
            }
        }
    }
    return found;
}

bool JumptableDetection::parseMakeBase(UDState *state, int reg) {
    LOG(1, "[MakeBase] looking for reference in 0x" << std::hex
        << state->getInstruction()->getAddress()
        << " register " << std::dec << reg);

    if(auto refList = state->getRegRef(reg)) {
        for(auto& s : *refList) {
            if(auto def = s->getRegDef(reg)) {
                TreeCapture cap;
                if(auto pageTree = dynamic_cast<TreeNodeAddress *>(def)) {
                    LOG(1, "table base make form 0x"
                        << std::hex << pageTree->getValue());
                    return true;
                }
            }
        }
    }
    return false;
}

bool JumptableDetection::parseTableOffset(UDState *state, int reg) {
    LOG(1, "[TableOffset] looking for reference in 0x" << std::hex
        << state->getInstruction()->getAddress()
        << " register " << std::dec << reg);

    if(auto refList = state->getRegRef(reg)) {
        for(auto& s : *refList) {
            if(auto def = s->getRegDef(reg)) {
                IF_LOG(1) def->print(TreePrinter(0, 0));
                LOG(1, "");

                TreeCapture cap1, cap2;
                if(TableOffsetForm1::matches(def, cap1)) {
                    LOG(1, "table offset form1!");
                    auto regTree1
                        = dynamic_cast<TreeNodePhysicalRegister *>(cap1.get(0));
                    auto regTree2
                        = dynamic_cast<TreeNodePhysicalRegister *>(cap1.get(1));
                    if(parseTableBase(s, regTree1->getRegister())) {
                        LOG(1, "[TableOffset]: FOUND!");
                        LOG(1, "with index reg of " << std::dec <<
                            regTree2->getRegister());
                        return true;
                    }
                }
                else if(TableOffsetForm2::matches(def, cap2)) {
                    LOG(1, "table offset form2!");
                    auto regTree1
                        = dynamic_cast<TreeNodePhysicalRegister *>(cap2.get(0));
                    auto regTree2
                        = dynamic_cast<TreeNodePhysicalRegister *>(cap2.get(1));
                    if(parseTableBase(s, regTree1->getRegister())) {
                        LOG(1, "[TableOffset]: FOUND!");
                        LOG(1, "with index reg of " << std::dec <<
                            regTree2->getRegister());
                        return true;
                    }
                }
            }
        }
    }
    return false;
}

bool JumptableDetection::containsIndirectJump() const {
    for(auto block : CIter::children(function)) {
        auto instr = block->getChildren()->getIterable()->getLast();
        auto s = instr->getSemantic();
        if(dynamic_cast<IndirectJumpInstruction *>(s)) {
            return true;
        }
    }
    return false;
}
