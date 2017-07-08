#include "jumptabledetection.h"
#include "analysis/walker.h"
#include "analysis/usedef.h"
#include "analysis/usedefutil.h"
#include "chunk/concrete.h"
#include "instr/concrete.h"

#include "log/log.h"

#ifdef ARCH_AARCH64
void JumptableDetection::detect(Function *function) {
    if(containsIndirectJump(function)) {
        ControlFlowGraph cfg(function);
        UDConfiguration config(&cfg);
        UDRegMemWorkingSet working(function, &cfg);
        UseDef usedef(&config, &working);

        cfg.dump();
        cfg.dumpDot();

        SccOrder order(&cfg);
        order.genFull(0);
        usedef.analyze(order.get());

        detect(&working);
    }
}

void JumptableDetection::detect(UDRegMemWorkingSet *working) {
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

    for(auto block : CIter::children(working->getFunction())) {
        auto instr = block->getChildren()->getIterable()->getLast();
        auto s = instr->getSemantic();
        if(dynamic_cast<IndirectJumpInstruction *>(s)) {
            LOG(5, "indirect jump at 0x" << std::hex << instr->getAddress());

            JumptableInfo info;
            auto parser = [&](auto state, TreeCapture cap) {
                return parseJumptable(state, cap, &info);
            };

            auto state = working->getState(instr);
            auto reg = state->getRegRefList().begin()->first;

            FlowUtil::searchUpDef<MakeJumpTargetForm1>(state, reg, parser);
            if(info.valid) {
                makeDescriptor(working, instr, info);
                check(instr, true);
                continue;
            }

            FlowUtil::searchUpDef<MakeJumpTargetForm2>(state, reg, parser);
            if(info.valid) {
                makeDescriptor(working, instr, info);
                check(instr, true);
                continue;
            }

            check(instr, false);
        }
    }
}

bool JumptableDetection::containsIndirectJump(Function *function) const {
    for(auto block : CIter::children(function)) {
        auto instr = block->getChildren()->getIterable()->getLast();
        auto s = instr->getSemantic();
        if(dynamic_cast<IndirectJumpInstruction *>(s)) {
            return true;
        }
    }
    return false;
}

bool JumptableDetection::parseJumptable(UDState *state, TreeCapture cap,
    JumptableInfo *info) {

    auto regTree1 = dynamic_cast<TreeNodePhysicalRegister *>(cap.get(0));
    auto regTree2 = dynamic_cast<TreeNodePhysicalRegister *>(cap.get(1));

    address_t targetBase = parseBaseAddress(state, regTree1->getRegister());
    address_t tableBase = 0;
    if(targetBase != 0) {
        LOG(9, "index 0: matches table base form");
        tableBase = parseTableAccess(state, regTree2->getRegister());
    }
    if(tableBase == 0) {
        targetBase = parseBaseAddress(state, regTree2->getRegister());
        if(targetBase > 0) {
            LOG(9, "index 1: matches table base form");
            tableBase = parseTableAccess(state, regTree1->getRegister());
        }
    }
    if(tableBase != 0) {
        info->valid = true;
        info->targetBase = targetBase;
        info->tableBase = tableBase;
        return true;
    }
    return false;
}

void JumptableDetection::makeDescriptor(UDRegMemWorkingSet *working,
    Instruction *instruction, const JumptableInfo &info) {

    auto jt = new JumpTableDescriptor(working->getFunction(), instruction);
    jt->setAddress(info.tableBase);
    jt->setTargetBaseAddress(info.targetBase);
    tableList.push_back(jt);
}

address_t JumptableDetection::parseBaseAddress(UDState *state, int reg) {
    LOG(1, "[TableBase] looking for reference in 0x" << std::hex
        << state->getInstruction()->getAddress()
        << " register " << std::dec << reg);

    typedef TreePatternCapture<
        TreePatternTerminal<TreeNodeAddress>
    > BaseAddressForm;

    address_t addr = 0;
    auto parser = [&](auto state, TreeCapture cap) {
        auto pageTree = dynamic_cast<TreeNodeAddress *>(cap.get(0));
        addr = pageTree->getValue();
        return true;
    };
    FlowUtil::searchUpDef<BaseAddressForm>(state, reg, parser);
    if(addr != 0) {
        return addr;
    }

    if(auto address = parseComputedAddress(state, reg)) {
        return address;
    }
    return parseSavedAddress(state, reg);
}

address_t JumptableDetection::parseSavedAddress(UDState *state, int reg) {
    typedef TreePatternUnary<TreeNodeDereference,
        TreePatternCapture<TreePatternBinary<TreeNodeAddition,
            TreePatternTerminal<TreeNodePhysicalRegister>,
            TreePatternTerminal<TreeNodeConstant>>
        >
    > LoadForm;

    address_t addr = 0;
    auto parser = [&](auto state, TreeCapture cap) {
        MemLocation loadLoc(cap.get(0));
        for(auto& ss : state->getMemRef(reg)) {
            for(const auto& mem : ss->getMemDefList()) {
                MemLocation storeLoc(mem.second);
                if(loadLoc == storeLoc) {
                    if(auto address = parseBaseAddress(ss, mem.first)) {
                        addr = address;
                        return true;
                    }
                }
            }
        }
        return false;
    };
    FlowUtil::searchUpDef<LoadForm>(state, reg, parser);
    return addr;
}

address_t JumptableDetection::parseComputedAddress(UDState *state, int reg) {
    typedef TreePatternBinary<TreeNodeAddition,
        TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>,
        TreePatternCapture<TreePatternTerminal<TreeNodeConstant>>
    > MakeBaseAddressForm;

    address_t addr = 0;
    auto parser = [&](auto state, TreeCapture cap) {
        auto regTree = dynamic_cast<TreeNodePhysicalRegister *>(cap.get(0));
        if(auto page = parseBaseAddress(state, regTree->getRegister())) {
            auto offsetTree = dynamic_cast<TreeNodeConstant *>(cap.get(1));
            addr = page + offsetTree->getValue();
            return true;
        }
        return false;
    };
    FlowUtil::searchUpDef<MakeBaseAddressForm>(state, reg, parser);
    return addr;
}

address_t JumptableDetection::parseTableAccess(UDState *state, int reg) {
    typedef TreePatternUnary<TreeNodeDereference,
        TreePatternBinary<TreeNodeAddition,
            TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>,
            TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>
        >
    > TableAccessForm1;

    typedef TreePatternUnary<TreeNodeDereference,
        TreePatternBinary<TreeNodeAddition,
            TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>,
            TreePatternBinary<TreeNodeLogicalShiftLeft,
                TreePatternCapture<
                    TreePatternTerminal<TreeNodePhysicalRegister>>,
                TreePatternCapture<TreePatternTerminal<TreeNodeConstant>>
            >
        >
    > TableAccessForm2;

    address_t addr = 0;
    auto parser = [&](auto state, TreeCapture cap) {
        auto regTree1 = dynamic_cast<TreeNodePhysicalRegister *>(cap.get(0));
        auto regTree2 = dynamic_cast<TreeNodePhysicalRegister *>(cap.get(1));
        if(auto address = parseBaseAddress(state, regTree1->getRegister())) {
            LOG(5, "[TableIndex]: FOUND!");
            LOG(9, "with index reg of " << std::dec <<
                regTree2->getRegister());
            addr = address;
            return true;
        }
        return false;
    };

    LOG(5, "[TableAccess] looking for reference in 0x" << std::hex
        << state->getInstruction()->getAddress()
        << " register " << std::dec << reg);

    FlowUtil::searchUpDef<TableAccessForm1>(state, reg, parser);
    if(addr > 0) {
        return addr;
    }
    FlowUtil::searchUpDef<TableAccessForm2>(state, reg, parser);
    return addr;
}

void JumptableDetection::check(Instruction *instruction, bool found) const {
    auto function = instruction->getParent()->getParent();
    auto module = dynamic_cast<Module *>(function->getParent()->getParent());

    bool wasFound = false;
    auto jumptablelist = module->getJumpTableList();
    JumpTableDescriptor *d = nullptr;
    for(auto jt : CIter::children(jumptablelist)) {
        if(jt->getInstruction() == instruction) {
            wasFound = true;
            d = jt->getDescriptor();
            break;
        }
    }

    if(found != wasFound) {
        LOG(1, "JumpTable MISMATCH: "
            << (found ? "(was not found)" : "(not found)")
            << " 0x" << std::hex << instruction->getAddress());
        return;
    }
    if(found && d) {
        JumpTableDescriptor *d2 = tableList.back();
        if(d->getAddress() != d2->getAddress()) {
            LOG(1, "JumpTable MISMATCH (address): 0x" << std::hex
                << d->getAddress() << " vs 0x" << d2->getAddress());
        }
        if(d->getTargetBaseAddress() != d2->getTargetBaseAddress()) {
            LOG(1, "JumpTable MISMATCH (target base address): 0x" << std::hex
                << d->getAddress() << " vs 0x" << d2->getAddress());
        }
    }
}
#endif

