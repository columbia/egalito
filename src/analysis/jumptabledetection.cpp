#include "jumptabledetection.h"
#include "analysis/walker.h"
#include "chunk/concrete.h"
#include "instr/concrete.h"

#include "log/log.h"

#ifdef ARCH_AARCH64
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
    typedef TreePatternBinary<TreeNodeAddition,
        TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>,
        TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>
    > MakeJumpTargetForm1;

    typedef TreePatternBinary<TreeNodeAddition,
        TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>,
            TreePatternBinary<TreeNodeLogicalShiftLeft,
                TreePatternCapture<
                    TreePatternTerminal<TreeNodePhysicalRegister>>,
                TreePatternCapture<TreePatternTerminal<TreeNodeConstant>>
            >
    > MakeJumpTargetForm2;

    checkFlag = false;
    LOG(5, "indirect jump at 0x" << std::hex
        << state->getInstruction()->getAddress());

    auto regRefList = state->getRegRefList();
    auto it = regRefList.cbegin();
    if(it != regRefList.cend()) {   // may not be found if producer was skipped
        auto reg = it->first;
        LOG0(9, " reg = " << std::dec << reg);
        for(auto s : it->second) {
            auto def = s->getRegDef(reg);
            if(!def) {
                LOG(9, " definition not found");
                continue;
            }

            LOG0(9, " defined as: ");
            IF_LOG(9) def->print(TreePrinter(0, 0));
            LOG(9, "");

            TreeCapture cap1, cap2;
            if(MakeJumpTargetForm1::matches(def, cap1)) {
                LOG(9, "matches jump target form1!");
                auto regTree1
                    = dynamic_cast<TreeNodePhysicalRegister *>(cap1.get(0));
                auto regTree2
                    = dynamic_cast<TreeNodePhysicalRegister *>(cap1.get(1));

                if(parseBaseAddress(s, regTree1->getRegister())) {
                    LOG(9, "index 0: matches table base form");
                    checkFlag =
                        parseJumpOffset(s, regTree2->getRegister());
                }
                else if(parseBaseAddress(s, regTree2->getRegister())) {
                    LOG(9, "index 1: matches table base form");
                    checkFlag =
                        parseJumpOffset(s, regTree1->getRegister());
                }
            }
            else if(MakeJumpTargetForm2::matches(def, cap2)) {
                LOG(9, "matches jump target form2!");
                auto regTree1
                    = dynamic_cast<TreeNodePhysicalRegister *>(cap2.get(0));
                auto regTree2
                    = dynamic_cast<TreeNodePhysicalRegister *>(cap2.get(1));

                if(parseBaseAddress(s, regTree1->getRegister())) {
                    LOG(9, "index 0: matches table base form");
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
                            throw "unknown form of table jump?";
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
    FlowUtil::collectUpDef(state, reg, pm);
    for(auto& capList : pm.getList()) {
        auto pageTree = dynamic_cast<TreeNodeAddress *>(capList[0].tree);
        LOG(5, "address 0x" << std::hex << pageTree->getValue());
    }
    if(pm.getList().size() > 0) return true;

    if(parseComputedAddress(state, reg)) {
        return true;
    }
    return parseSavedAddress(state, reg);
}

bool JumptableDetection::parseComputedAddress(UDState *state, int reg) {
    typedef TreePatternBinary<TreeNodeAddition,
        TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>,
        TreePatternTerminal<TreeNodeConstant>
    > MakeBaseAddressForm;

    FlowPatternMatch<MakeBaseAddressForm> pm;
    FlowUtil::collectUpDef(state, reg, pm);

    if(pm.getCount() > 0) {
        LOG(9, "match compute address");
    }
    for(auto capList : pm.getList()) {
        auto upState = capList[0].state;
        auto regTree
            = dynamic_cast<TreeNodePhysicalRegister *>(capList[0].tree);
        if(parseBaseAddress(upState, regTree->getRegister())) {
            return true;
        }
    }
    return false;
}

bool JumptableDetection::parseSavedAddress(UDState *state, int reg) {
    typedef TreePatternUnary<TreeNodeDereference,
        TreePatternCapture<TreePatternBinary<TreeNodeAddition,
            TreePatternTerminal<TreeNodePhysicalRegister>,
            TreePatternTerminal<TreeNodeConstant>>
        >
    > LoadForm;

    FlowPatternMatch<LoadForm> pm;
    FlowUtil::collectUpDef(state, reg, pm);
    for(auto capList : pm.getList()) {
        auto upState = capList[0].state;
        auto target = capList[0].reg;

        if(target != reg) continue;

        MemLocation load(capList[0].tree);
        for(auto& s : upState->getMemRef(reg)) {
            for(const auto& mem : s->getMemDefList()) {
                MemLocation store(mem.second);
                if(load == store) {
                    if(parseBaseAddress(s, mem.first)) {
                        return true;
                    }
                }
            }
        }
    }
    return false;
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

    LOG(5, "[JumpOffset] looking for reference in 0x" << std::hex
        << state->getInstruction()->getAddress()
        << " register " << std::dec << reg);

    FlowPatternMatch<TableOffsetForm1> pm1;
    FlowUtil::collectUpDef(state, reg, pm1);
    if(pm1.getList().size() > 0) {
        LOG(9, "table offset form1!");
        return parseTableIndex(pm1.getList());
    }

    FlowPatternMatch<TableOffsetForm2> pm2;
    FlowUtil::collectUpDef(state, reg, pm2);
    if(pm2.getList().size() > 0) {
        LOG(9, "table offset form2!");
        return parseTableIndex(pm2.getList());
    }

    return false;
}

bool JumptableDetection::parseTableIndex(
    const std::vector<std::vector<FlowMatchResult>>& list) {

    for(auto& capList : list) {
        auto upState = capList[0].state;
        auto regTree1
            = dynamic_cast<TreeNodePhysicalRegister *>(capList[0].tree);
        auto regTree2
            = dynamic_cast<TreeNodePhysicalRegister *>(capList[0].tree);

        if(parseBaseAddress(upState, regTree1->getRegister())) {
            LOG(5, "[TableIndex]: FOUND!");
            LOG(9, "with index reg of " << std::dec <<
                regTree2->getRegister());
            return true;
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
#endif
