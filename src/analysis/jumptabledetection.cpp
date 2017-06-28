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

                if(parseBaseAddress(s, regTree1->getRegister())) {
                    LOG(1, "index 0: matches table base form");
                    checkFlag =
                        parseJumpOffset(s, regTree2->getRegister());
                }
                else if(parseBaseAddress(s, regTree2->getRegister())) {
                    LOG(1, "index 1: matches table base form");
                    checkFlag =
                        parseJumpOffset(s, regTree1->getRegister());
                }
            }
            else if(MakeJumpTargetForm2::matches(def, cap2)) {
                LOG(1, "matches jump target form2!");
                auto regTree1
                    = dynamic_cast<TreeNodePhysicalRegister *>(cap2.get(0));
                auto regTree2
                    = dynamic_cast<TreeNodePhysicalRegister *>(cap2.get(1));

                if(parseBaseAddress(s, regTree1->getRegister())) {
                    LOG(1, "index 0: matches table base form");
                    checkFlag =
                        parseJumpOffset(s, regTree2->getRegister());
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

bool JumptableDetection::parseBaseAddress(UDState *state, int reg) {
    LOG(1, "[TableBase] looking for reference in 0x" << std::hex
        << state->getInstruction()->getAddress()
        << " register " << std::dec << reg);

    typedef TreePatternCapture<
        TreePatternTerminal<TreeNodeAddress>
    > BaseAddressForm;

    FlowPatternMatch<BaseAddressForm> pm;
    BackFlow::collectUpDef(state, reg, pm);
    for(auto& capList : pm.getList()) {
        auto pageTree = dynamic_cast<TreeNodeAddress *>(capList[0].tree);
        LOG(1, "address 0x" << std::hex << pageTree->getValue());
    }
    if(pm.getList().size() > 0) return true;

    typedef TreePatternBinary<TreeNodeAddition,
        TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>,
        TreePatternTerminal<TreeNodeConstant>
    > MakeBaseAddressForm;

    bool found = false;
    FlowPatternDeepMatch<MakeBaseAddressForm> deep1;
    BackFlow::collectUpDef(state, reg, deep1);
    if(deep1.getCount() > 0) {
        LOG(1, "deep match1");
        for(auto capList : deep1.getList()) {
            auto upState = capList[0].state;
            auto regTree
                = dynamic_cast<TreeNodePhysicalRegister *>(capList[0].tree);

            LOG(9, "    state = 0x"
                << std::hex << upState->getInstruction()->getAddress());
            LOG0(9, "    regTree: ");
            IF_LOG(9) regTree->print(TreePrinter(0, 0));
            LOG(9, "");
            found |= parseBaseAddress(upState, regTree->getRegister());
        }
    }
    return found;
}

bool JumptableDetection::parseJumpOffset(UDState *state, int reg) {
    typedef TreePatternUnary<TreeNodeDereference,
        TreePatternBinary<TreeNodeAddition,
            TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>,
            TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>
        >
    > TableOffsetForm1;

    typedef TreePatternUnary<TreeNodeDereference,
        TreePatternBinary<TreeNodeAddition,
            TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>,
            TreePatternBinary<TreeNodeLogicalShiftLeft,
                TreePatternCapture<
                    TreePatternTerminal<TreeNodePhysicalRegister>>,
                TreePatternCapture<TreePatternTerminal<TreeNodeConstant>>
            >
        >
    > TableOffsetForm2;

    LOG(1, "[JumpOffset] looking for reference in 0x" << std::hex
        << state->getInstruction()->getAddress()
        << " register " << std::dec << reg);

    FlowPatternMatch<TableOffsetForm1> pm1;
    BackFlow::collectUpDef(state, reg, pm1);
    if(pm1.getList().size() > 0) {
        LOG(1, "table offset form1!");
        return parseTableIndex(pm1.getList());
    }

    FlowPatternMatch<TableOffsetForm2> pm2;
    BackFlow::collectUpDef(state, reg, pm2);
    if(pm2.getList().size() > 0) {
        LOG(1, "table offset form2!");
        return parseTableIndex(pm2.getList());
    }

    return false;
}

bool JumptableDetection::parseTableIndex(
    const std::vector<std::vector<FlowMatchResult>>& list) {

    bool found = false;
    for(auto& capList : list) {
        auto upState = capList[0].state;
        auto regTree1
            = dynamic_cast<TreeNodePhysicalRegister *>(capList[0].tree);
        auto regTree2
            = dynamic_cast<TreeNodePhysicalRegister *>(capList[0].tree);

        if(parseBaseAddress(upState, regTree1->getRegister())) {
            LOG(1, "[TableIndex]: FOUND!");
            LOG(1, "with index reg of " << std::dec <<
                regTree2->getRegister());
            found = true;
        }
    }
    return found;
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

