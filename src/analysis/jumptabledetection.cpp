#include "jumptabledetection.h"
#include "analysis/walker.h"
#include "analysis/usedef.h"
#include "analysis/usedefutil.h"
#include "chunk/concrete.h"
#include "instr/concrete.h"

#include "log/log.h"
#include "log/temp.h"

#ifdef ARCH_AARCH64
void JumptableDetection::detect(Module *module) {
    for(auto f : CIter::functions(module)) {
        detect(f);
    }
}

void JumptableDetection::detect(Function *function) {
    if(containsIndirectJump(function)) {
        //TemporaryLogLevel tll("analysis", 10);
        ControlFlowGraph cfg(function);
        UDConfiguration config(&cfg);
        UDRegMemWorkingSet working(function, &cfg);
        UseDef usedef(&config, &working);

        IF_LOG(10) cfg.dump();
        IF_LOG(10) cfg.dumpDot();

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
            LOG(10, "indirect jump at 0x" << std::hex << instr->getAddress());
            auto state = working->getState(instr);
            IF_LOG(10) state->dumpState();

            JumptableInfo info(working->getCFG(), working, state);
            auto parser = [&](UDState *s, TreeCapture& cap) {
                return parseJumptable(s, cap, &info);
            };

            LOG(10, "trying MakeJumpTargetForm1");
            auto assembly = s->getAssembly();
            auto op0 = assembly->getAsmOperands()->getOperands()[0].reg;
            int reg = AARCH64GPRegister::convertToPhysical(op0);
            FlowUtil::searchUpDef<MakeJumpTargetForm1>(state, reg, parser);
            if(info.valid) {
                makeDescriptor(working, instr, info);
                continue;
            }

            LOG(10, "trying MakeJumpTargetForm2");
            FlowUtil::searchUpDef<MakeJumpTargetForm2>(state, reg, parser);
            if(info.valid) {
                makeDescriptor(working, instr, info);
                continue;
            }
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

    bool found = false;
    address_t targetBase;
    std::tie(found, targetBase)
        = parseBaseAddress(state, regTree1->getRegister());
    if(found) {
        LOG(10, "index 0: matches table base form");
        found = parseTableAccess(state, regTree2->getRegister(), info);
    }
    if(!found) {
        std::tie(found, targetBase)
            = parseBaseAddress(state, regTree2->getRegister());
        if(targetBase > 0) {
            LOG(10, "index 1: matches table base form");
            found = parseTableAccess(state, regTree1->getRegister(), info);
        }
    }
    if(found) {
        info->valid = true;
        info->targetBase = targetBase;
        return true;
    }
    return false;
}

void JumptableDetection::makeDescriptor(UDRegMemWorkingSet *working,
    Instruction *instruction, const JumptableInfo &info) {

    auto jt = new JumpTableDescriptor(working->getFunction(), instruction);
    jt->setAddress(info.tableBase);
    jt->setTargetBaseAddress(info.targetBase);
    jt->setScale(info.scale);
    //jt->setIndexExpr(info.indexExpr);
    jt->setEntries(info.entries);
    tableList.push_back(jt);
}

bool JumptableDetection::parseTableAccess(UDState *state, int reg,
    JumptableInfo *info) {

    typedef TreePatternCapture<TreePatternUnary<TreeNodeDereference,
        TreePatternBinary<TreeNodeAddition,
            TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>,
            TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>
        >
    >> TableAccessForm1;

    typedef TreePatternCapture<TreePatternUnary<TreeNodeDereference,
        TreePatternBinary<TreeNodeAddition,
            TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>,
            TreePatternBinary<TreeNodeLogicalShiftLeft,
                TreePatternCapture<
                    TreePatternTerminal<TreeNodePhysicalRegister>>,
                TreePatternCapture<TreePatternTerminal<TreeNodeConstant>>
            >
        >
    >> TableAccessForm2;

    bool found = false;
    auto parser = [&, info](UDState *s, TreeCapture& cap) {
        auto regTree1 = dynamic_cast<TreeNodePhysicalRegister *>(cap.get(1));
        auto regTree2 = dynamic_cast<TreeNodePhysicalRegister *>(cap.get(2));

        address_t address;
        std::tie(found, address)
            = parseBaseAddress(s, regTree1->getRegister());
        if(found) {
            LOG(10, "JUMPTABLE FOUND!");
            info->tableBase = address;

            auto deref = dynamic_cast<TreeNodeDereference *>(cap.get(0));
            info->scale = deref->getWidth();

            parseBound(s, regTree2->getRegister(), info);
            return true;
        }
        return false;
    };

    LOG(10, "[TableAccess] looking for reference in 0x" << std::hex
        << state->getInstruction()->getAddress()
        << " register " << std::dec << reg);
    IF_LOG(10) state->dumpState();

    LOG(10, "    trying TableAccessForm1");
    FlowUtil::searchUpDef<TableAccessForm1>(state, reg, parser);
    if(found) {
        return true;
    }
    LOG(10, "    trying TableAccessForm2");
    FlowUtil::searchUpDef<TableAccessForm2>(state, reg, parser);
    if(found) {
        return true;
    }
    return false;
}

auto JumptableDetection::parseBaseAddress(UDState *state, int reg)
    -> std::tuple<bool, address_t> {

    LOG(10, "[TableBase] looking for reference in 0x" << std::hex
        << state->getInstruction()->getAddress()
        << " register " << std::dec << reg);
    IF_LOG(10) state->dumpState();

    typedef TreePatternCapture<
        TreePatternTerminal<TreeNodeAddress>
    > BaseAddressForm;

    address_t addr = 0;
    bool found = false;
    auto parser = [&](UDState *s, TreeCapture& cap) {
        auto pageTree = dynamic_cast<TreeNodeAddress *>(cap.get(0));
        addr = pageTree->getValue();
        found = true;
        return true;
    };
    FlowUtil::searchUpDef<BaseAddressForm>(state, reg, parser);
    if(found) {
        return std::make_tuple(true, addr);
    }

    std::tie(found, addr) = parseComputedAddress(state, reg);
    if(found) {
        return std::make_tuple(true, addr);
    }
    return parseSavedAddress(state, reg);
}

auto JumptableDetection::parseSavedAddress(UDState *state, int reg)
    -> std::tuple<bool, address_t> {
    typedef TreePatternUnary<TreeNodeDereference,
        TreePatternCapture<TreePatternBinary<TreeNodeAddition,
            TreePatternTerminal<TreeNodePhysicalRegister>,
            TreePatternTerminal<TreeNodeConstant>>
        >
    > LoadForm;

    address_t addr = 0;
    bool found = false;
    auto parser = [&](UDState *s, TreeCapture& cap) {
        MemLocation loadLoc(cap.get(0));
        for(auto& ss : s->getMemRef(reg)) {
            for(const auto& mem : ss->getMemDefList()) {
                MemLocation storeLoc(mem.second);
                if(loadLoc == storeLoc) {
                    address_t address;
                    std::tie(found, address) = parseBaseAddress(ss, mem.first);
                    if(found) {
                        addr = address;
                        return true;
                    }
                }
            }
        }
        return false;
    };
    FlowUtil::searchUpDef<LoadForm>(state, reg, parser);
    return std::make_tuple(found, addr);
}

auto JumptableDetection::parseComputedAddress(UDState *state, int reg)
    -> std::tuple<bool, address_t> {
    typedef TreePatternBinary<TreeNodeAddition,
        TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>,
        TreePatternCapture<TreePatternTerminal<TreeNodeConstant>>
    > MakeBaseAddressForm;

    address_t addr = 0;
    bool found;
    auto parser = [&](UDState *s, TreeCapture& cap) {
        auto regTree = dynamic_cast<TreeNodePhysicalRegister *>(cap.get(0));
        address_t page;
        std::tie(found, page) = parseBaseAddress(s, regTree->getRegister());
        if(found) {
            auto offsetTree = dynamic_cast<TreeNodeConstant *>(cap.get(1));
            addr = page + offsetTree->getValue();
            return true;
        }
        return false;
    };
    FlowUtil::searchUpDef<MakeBaseAddressForm>(state, reg, parser);
    return std::make_pair(found, addr);
}

bool JumptableDetection::parseBound(UDState *state, int reg,
    JumptableInfo *info) {

    typedef TreePatternBinary<TreeNodeComparison,
        TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>,
        TreePatternCapture<TreePatternTerminal<TreeNodeConstant>>
    > ComparisonForm;

    bool found = false;
    auto parser = [&, info](UDState *s, int reg, TreeCapture& cap) {
        if(reg == AARCH64GPRegister::NZCV) { // cmp
            auto boundTree = dynamic_cast<TreeNodeConstant *>(cap.get(1));
            if(getBoundFromCompare(s, boundTree->getValue(), info)) {
                LOG(10, "NZCV 0x"
                    << std::hex << s->getInstruction()->getAddress());
                found = true;
            }
        }
        if(reg == AARCH64GPRegister::ONETIME_NZCV) { // cbz, cbnz
            auto regTree = dynamic_cast<TreeNodePhysicalRegister *>(cap.get(0));
            if(getBoundFromCompareAndBranch(s, regTree->getRegister(),
                info)) {

                LOG(10, "ONETIME NZCV: 0x"
                    << std::hex << s->getInstruction()->getAddress());
                found = true;
            }
        }
        return found;
    };

    LOG(10, "parseBound 0x"
        << std::hex << state->getInstruction()->getAddress()
        << " reg " << std::dec << reg);
    IF_LOG(10) state->dumpState();

    // search up where reg is defined and look downward
    for(auto s : state->getRegRef(reg)) {
        // first check if there is any use (other than this)
        FlowUtil::searchDownDef<ComparisonForm>(s, reg, parser);
        if(found) break;

        // if not
        if(getBoundFromMove(s, reg, info)) {
            found = true;
            break;
        }
        if(getBoundFromIndexTable(s, reg, info)) {
            found = true;
            break;
        }
    }

    // more expensive in general
    if(!found && state->getRegRef(reg).size() == 0) {
        if(getBoundFromArgument(state, reg, info)) {
            found = true;
        }
    }
    if(found) {
        LOG(10, "entries = " << info->entries);
    }
    if(!found) {
        LOG(10, "no condition?");
    }
    LOG(10, "======");
    return found;
}

bool JumptableDetection::getBoundFromCompare(UDState *state, int bound,
    JumptableInfo *info) {

    std::vector<UDState *> branches;

    auto jumpNodeID = info->jumpState->getNode()->getID();
    for(auto s : state->getRegUse(AARCH64GPRegister::NZCV)) {
        LOG(10, "s = 0x" << s->getInstruction()->getAddress());
        IF_LOG(10) s->dumpState();

        for(auto link : s->getNode()->forwardLinks()) {
            if(link.getID() == jumpNodeID) {
                branches.push_back(s);
            }
        }
    }

    for(auto s : branches) {
        auto assembly = s->getInstruction()->getSemantic()->getAssembly();
        if(assembly->getMnemonic() == "b.ne") continue;
        if(assembly->getMnemonic() == "b.eq") continue;
        if(assembly->getMnemonic() == "b.ls") {
            LOG(10, "should be lower or same (<=)");
            info->entries = bound + 1;
            return true;
        }
        else if(assembly->getMnemonic() == "b.hi") {
            LOG(10, "should (NOT) be higher (!>)");
            info->entries = bound + 1;
            return true;
        }
        else {
            LOG(9, "unknown corresponding branch at 0x" << std::hex
                << s->getInstruction()->getAddress()
                << " " << assembly->getMnemonic());
        }
    }
    return false;
}

bool JumptableDetection::getBoundFromCompareAndBranch(UDState *state, int reg,
    JumptableInfo *info) {

    auto jumpNodeID = info->jumpState->getNode()->getID();

    for(auto link : state->getNode()->forwardLinks()) {
        if(link.getID() == jumpNodeID) {
            LOG(1, "NYI: condition register is " << reg);
            break;
        }
    }
    return false;
}

bool JumptableDetection::getBoundFromMove(UDState *state, int reg,
    JumptableInfo *info) {

    auto def = state->getRegDef(reg);
    if(auto tree = dynamic_cast<TreeNodePhysicalRegister *>(def)) {
        LOG(10, "MOVE -- recurse");
        if(parseBound(state, tree->getRegister(), info)) {
            return true;
        }
    }
    return false;
}

// this only exists for manually crafted jumptable in printf
bool JumptableDetection::getBoundFromIndexTable(UDState *state, int reg,
    JumptableInfo *info) {

    typedef TreePatternUnary<TreeNodeDereference,
        TreePatternBinary<TreeNodeAddition,
            TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>,
            TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>
        >
    > IndexTableAccessForm;

    typedef TreePatternBinary<TreeNodeAddition,
        TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>,
        TreePatternCapture<TreePatternTerminal<TreeNodeConstant>>
    > MakeTableIndexForm;

    TreeCapture cap;
    if(IndexTableAccessForm::matches(state->getRegDef(reg), cap)) {
        LOG(5, "Dereference from index table 0x" << std::hex
            << state->getInstruction()->getAddress());
        bool found = false;

        auto parser = [&, info](UDState *s, TreeCapture& cap) {
            auto boundTree = dynamic_cast<TreeNodeConstant *>(cap.get(1));
            info->entries = boundTree->getValue() / info->scale;
            found = true;
            return true;
        };

        auto baseRegTree = dynamic_cast<TreeNodePhysicalRegister *>(cap.get(0));
        LOG(10, "look for reg " << baseRegTree->getRegister());
        FlowUtil::searchUpDef<MakeTableIndexForm>(
            state, baseRegTree->getRegister(), parser);
        return found;
    }
    return false;
}

bool JumptableDetection::getBoundFromArgument(UDState *state, int reg,
    JumptableInfo *info) {

    typedef TreePatternBinary<TreeNodeComparison,
        TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>,
        TreePatternCapture<TreePatternTerminal<TreeNodeConstant>>
    > ComparisonForm;

    ReverseReversePostorder order(info->cfg);
    order.gen(info->jumpState->getNode()->getID());

    // the register should be the same, otherwise it must have a def tree
    bool found = false;
    auto parser = [&, info](UDState *s, TreeCapture& cap) {
        auto regTree = dynamic_cast<TreeNodePhysicalRegister *>(cap.get(0));
        if(regTree->getRegister() != reg) return false;
        auto boundTree = dynamic_cast<TreeNodeConstant *>(cap.get(1));
        if(getBoundFromCompare(s, boundTree->getValue(), info)) {
            found = true;
            return true;
        }
        return false;
    };

    auto vec = order.get()[0];
    for(auto it = vec.begin() + 1; it != vec.end(); ++it) {
        LOG(10, "checking " << *it);
        auto block = info->cfg->get(*it)->getBlock();
        auto instr = block->getChildren()->getIterable()->getLast();
        auto s = info->working->getState(instr);
        FlowUtil::searchUpDef<ComparisonForm>(
            s, AARCH64GPRegister::NZCV, parser);    // ONETIME_NZCV is NYI
        if(found) {
            return true;
        }
    }
    return false;
}
#endif

