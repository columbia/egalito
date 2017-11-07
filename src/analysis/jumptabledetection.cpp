#include "jumptabledetection.h"
#include "analysis/walker.h"
#include "analysis/usedef.h"
#include "analysis/usedefutil.h"
#include "chunk/concrete.h"
#include "instr/concrete.h"

#include "log/log.h"
#include "log/temp.h"

void JumptableDetection::detect(Module *module) {
    for(auto f : CIter::functions(module)) {
        detect(f);
    }
}

void JumptableDetection::detect(Function *function) {
    if(containsIndirectJump(function)) {
        //TemporaryLogLevel tll("analysis", 11, function->hasName("_IO_vfprintf"));
        //TemporaryLogLevel tll("analysis", 11, function->hasName("_IO_vfscanf"));
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
#ifdef ARCH_X86_64
    typedef TreePatternBinary<TreeNodeAddition,
        TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>,
        TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>
    > MakeJumpTargetForm1;

    for(auto block : CIter::children(working->getFunction())) {
        auto instr = block->getChildren()->getIterable()->getLast();
        auto s = instr->getSemantic();
        if(auto ij = dynamic_cast<IndirectJumpInstruction *>(s)) {
            auto mode = ij->getAssembly()->getAsmOperands()->getMode();
            if(mode != AssemblyOperands::MODE_REG) continue;
            LOG(10, "indirect jump at 0x" << std::hex << instr->getAddress());
            auto state = working->getState(instr);
            IF_LOG(10) state->dumpState();

            JumptableInfo info(working->getCFG(), working, state);
            auto parser = [&](UDState *s, TreeCapture& cap) {
                return parseJumptable(s, cap, &info);
            };

            LOG(10, "trying MakeJumpTargetForm1");
            int reg = X86Register::convertToPhysical(ij->getRegister());
            FlowUtil::searchUpDef<MakeJumpTargetForm1>(state, reg, parser);
            if(info.valid) {
                makeDescriptor(working, instr, info);
                continue;
            }
        }
    }
#elif defined(ARCH_AARCH64)
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
#endif
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

bool JumptableDetection::parseJumptable(UDState *state, TreeCapture& cap,
    JumptableInfo *info) {

#ifdef ARCH_X86_64
    auto regTree1 = dynamic_cast<TreeNodePhysicalRegister *>(cap.get(0));
    auto regTree2 = dynamic_cast<TreeNodePhysicalRegister *>(cap.get(1));
#elif defined(ARCH_AARCH64)
    auto regTree1 = dynamic_cast<TreeNodePhysicalRegister *>(cap.get(0));
    auto regTree2 = dynamic_cast<TreeNodePhysicalRegister *>(cap.get(1));
#endif

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

#ifdef ARCH_X86_64
    typedef TreePatternCapture<TreePatternUnary<TreeNodeDereference,
        TreePatternBinary<TreeNodeAddition,
            TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>,
            TreePatternBinary<TreeNodeMultiplication,
                TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>,
                TreePatternCapture<TreePatternTerminal<TreeNodeConstant>>
            >
        >
    >> TableAccessForm1;

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
    return false;
#elif defined(ARCH_AARCH64)
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
#endif
}

auto JumptableDetection::parseBaseAddress(UDState *state, int reg)
    -> std::tuple<bool, address_t> {

    LOG(10, "[TableBase] looking for reference in 0x" << std::hex
        << state->getInstruction()->getAddress()
        << " register " << std::dec << reg);
    IF_LOG(10) state->dumpState();

#ifdef ARCH_X86_64
    typedef TreePatternUnary<TreeNodeDereference,
        TreePatternBinary<TreeNodeAddition,
            TreePatternCapture<TreePatternRegisterIs<X86_REG_RIP>>,
            TreePatternCapture<TreePatternTerminal<TreeNodeAddress>>
        >
    > BaseAddressForm;

    address_t addr = 0;
    bool found = false;
    auto parser = [&](UDState *s, TreeCapture& cap) {
        auto ripTree = dynamic_cast<TreeNodeRegisterRIP *>(cap.get(0));
        auto dispTree = dynamic_cast<TreeNodeAddress *>(cap.get(1));
        addr = dispTree->getValue() + ripTree->getValue();
        found = true;
        return true;
    };
    FlowUtil::searchUpDef<BaseAddressForm>(state, reg, parser);
    if(found) {
        return std::make_tuple(true, addr);
    }

    return std::make_tuple(false, 0);
#elif defined(ARCH_AARCH64)
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
#endif
}

auto JumptableDetection::parseSavedAddress(UDState *state, int reg)
    -> std::tuple<bool, address_t> {

#ifdef ARCH_X86_64
    return std::make_tuple(false, 0);
#elif defined(ARCH_AARCH64)
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
#endif
}

auto JumptableDetection::parseComputedAddress(UDState *state, int reg)
    -> std::tuple<bool, address_t> {

#ifdef ARCH_X86_64
    return std::make_tuple(false, 0);
#elif defined(ARCH_AARCH64)
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
    return std::make_tuple(found, addr);
#endif
}

bool JumptableDetection::parseBound(UDState *state, int reg,
    JumptableInfo *info) {

#ifdef ARCH_X86_64
    bool found = false;

    LOG(10, "parseBound 0x"
        << std::hex << state->getInstruction()->getAddress()
        << " reg " << std::dec << reg);
    IF_LOG(10) state->dumpState();

    for(auto s : state->getRegRef(reg)) {
        if(s->getInstruction()->getParent()
            == state->getInstruction()->getParent()) {
            if(getBoundFromMove(s, reg, info)) {
                found = true;
                break;
            }
        }
    }
    if(!found) {
        if(getBoundFromArgument(state, reg, info)) {
            found = true;
        }
    }
    if(!found) {
        if(getBoundFromLoad(state, reg, info)) {
            found = true;
        }
    }
    if(!found) {
        if(getBoundFromBitTest(state, reg, info)) {
            found = true;
        }
    }
    if(!found) {
        for(auto s : state->getRegRef(reg)) {
            if(getBoundFromMove(s, reg, info)) {
                found = true;
                break;
            }

            if(getBoundFromAnd(s, reg, info)) {
                found = true;
                break;
            }

#if 0
            if(getBoundFromIndexTable(s, reg, info)) {
                found = true;
                break;
            }
#endif
        }
    }
    if(found) {
        LOG(10, "entries = " << std::dec << info->entries);
    }
    else {
        LOG(10, "no condition?");
    }
    LOG(10, "======");

    return found;
#elif defined(ARCH_AARCH64)
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
        LOG(10, "entries = " << std::dec << info->entries);
    }
    if(!found) {
        LOG(10, "no condition?");
    }
    LOG(10, "======");
    return found;
#endif
}

bool JumptableDetection::getBoundFromCompare(UDState *state, int bound,
    JumptableInfo *info) {

#ifdef ARCH_X86_64
    std::vector<UDState *> branches;

    LOG(10, "getBoundFromCompare " << std::dec << bound);
    auto jumpNodeID = info->jumpState->getNode()->getID();
    for(auto s : state->getRegUse(X86Register::FLAGS)) {
        LOG(10, "s = 0x" << std::hex << s->getInstruction()->getAddress());
        IF_LOG(10) s->dumpState();
        if(isReachable<Preorder>(
            info->cfg, state->getNode()->getID(), jumpNodeID)) {

            LOG(10, "this is reachable");
            branches.push_back(s);
        }
    }

    LOG(10, std::dec << branches.size() << " branches");
    for(auto s : branches) {
        auto semantic = s->getInstruction()->getSemantic();
        auto cfi = dynamic_cast<ControlFlowInstruction *>(semantic);
        if(!cfi) continue;

        auto mnemonic = cfi->getMnemonic();
        LOG(10, "branch " << mnemonic << " at " << std::hex << s->getInstruction()->getAddress());
        if(mnemonic == "jne") continue;
        if(mnemonic == "je") continue;
        if(mnemonic == "jle") {
            LOG(10, "should be lower or same (<=)");
            info->entries = bound + 1;
            return true;
        }
        else if(mnemonic == "jb") {
            LOG(10, "should be lower (<)");
            info->entries = bound;
            return true;
        }
        else if(mnemonic == "ja") {
            LOG(10, "should (NOT) be higher (!>)");
            info->entries = bound + 1;
            return true;
        }
        else if(mnemonic == "jae") {
            LOG(10, "should (NOT) be higher or same (!>=)");
            info->entries = bound;
            return true;
        }
        else {
            LOG(9, "unknown corresponding branch at 0x" << std::hex
                << s->getInstruction()->getAddress() << " " << mnemonic);
        }
    }
    return false;
#elif defined(ARCH_AARCH64)
    std::vector<UDState *> branches;

    auto jumpNodeID = info->jumpState->getNode()->getID();
    for(auto s : state->getRegUse(AARCH64GPRegister::NZCV)) {
        LOG(10, "s = 0x" << s->getInstruction()->getAddress());
        IF_LOG(10) s->dumpState();

        for(auto link : s->getNode()->forwardLinks()) {
            if(link->getTargetID() == jumpNodeID) {
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
#endif
}

bool JumptableDetection::getBoundFromCompareAndBranch(UDState *state, int reg,
    JumptableInfo *info) {

    auto jumpNodeID = info->jumpState->getNode()->getID();

    for(auto link : state->getNode()->forwardLinks()) {
        if(link->getTargetID() == jumpNodeID) {
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

bool JumptableDetection::getBoundFromAnd(UDState *state, int reg,
    JumptableInfo *info) {

    typedef TreePatternBinary<TreeNodeAnd,
        TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>,
        TreePatternCapture<TreePatternTerminal<TreeNodeConstant>>
    > AndForm;

    TreeCapture capture;
    if(AndForm::matches(state->getRegDef(reg), capture)) {
        LOG(10, "AndForm matches");
        IF_LOG(10) state->dumpState();
        auto boundTree = dynamic_cast<TreeNodeConstant *>(capture.get(1));
        info->entries = boundTree->getValue() +1;
        return true;
    }
    return false;
}

#ifdef ARCH_X86_64
bool JumptableDetection::getBoundFromLoad(UDState *state, int reg,
    JumptableInfo *info) {

    typedef TreePatternUnary<TreeNodeDereference,
        TreePatternCapture<TreePatternBinary<TreeNodeAddition,
            TreePatternTerminal<TreeNodePhysicalRegister>,
            TreePatternTerminal<TreeNodeAddress>
        >>
    > MemoryForm;

    typedef TreePatternBinary<TreeNodeComparison,
        TreePatternUnary<TreeNodeDereference,
            TreePatternCapture<TreePatternBinary<TreeNodeAddition,
                TreePatternTerminal<TreeNodePhysicalRegister>,
                TreePatternTerminal<TreeNodeAddress>
            >>
        >,
        TreePatternCapture<TreePatternTerminal<TreeNodeConstant>>
    > ComparisonForm;

    bool found = false;

    //std::vector<std::pair<UDState *, address_t>> loadStates;
    std::vector<std::pair<UDState *, MemLocation>> loadStates;
    auto parser1 = [&, info](UDState *s, TreeCapture& cap) {
        LOG(10, "s1 = " << s->getInstruction()->getAddress());
        IF_LOG(10) s->dumpState();
        loadStates.emplace_back(s, cap.get(0));
        return false;   // collect all
    };

    LOG(10, "getBoundFromLoad 0x"
        << std::hex << state->getInstruction()->getAddress()
        << " reg " << std::dec << reg);
    IF_LOG(10) state->dumpState();
    FlowUtil::searchUpDef<MemoryForm>(state, reg, parser1);
    if(loadStates.empty()) return false;

    for(const auto& pair : loadStates) {
        auto s = pair.first;
        auto& memLocation = pair.second;
        auto r = dynamic_cast<TreeNodePhysicalRegister *>(
            memLocation.getRegTree())->getRegister();
        LOG(10, "  r = " << std::dec << r);
        for(auto& s2 : s->getRegRef(r)) {
            LOG(10, "  s2 = " << std::hex << s->getInstruction()->getAddress());
            IF_LOG(10) s2->dumpState();
            LOG(10, "should look at use states in 0x"
                << std::hex << s2->getInstruction()->getAddress());
            for(auto& s3 : s2->getRegUse(r)) {
                TreeCapture capture;
                LOG(10, "s3 = " << std::hex
                    << s3->getInstruction()->getAddress());
                if(auto def = s3->getRegDef(X86Register::FLAGS)) {
                    LOG(10, "flags defined in "
                        << std::hex << s3->getInstruction()->getAddress());
                    IF_LOG(10) s3->dumpState();
                    if(ComparisonForm::matches(def, capture)) {
                        LOG(10, "  form matches!");
                        IF_LOG(10) capture.get(0)->print(TreePrinter(0, 0));
                        LOG(10, "");
                        if(memLocation != MemLocation(capture.get(0))) continue;
                        auto boundTree
                            = dynamic_cast<TreeNodeConstant *>(capture.get(1));
                        LOG(10, "matches!");
                        if(getBoundFromCompare(s3, boundTree->getValue(),
                            info)) {

                            LOG(10, "found!");
                            found = true;
                        }
                    }
                }
            }
        }
    }

    typedef TreePatternBinary<TreeNodeComparison,
        TreePatternTerminal<TreeNodePhysicalRegister>,
        TreePatternCapture<TreePatternTerminal<TreeNodeConstant>>
    > ComparisonForm2;

    if(!found) {
        LOG(10, "checking if there was store to this location");
        for(const auto& pair : loadStates) {
            for(auto& ref : pair.first->getMemRef(reg)) {
                for(auto& m : ref->getMemDefList()) {
                    if(pair.second == MemLocation(m.second)) {
                        for(auto& def : ref->getRegRef(m.first)) {
                            for(auto& use : def->getRegUse(m.first)) {
                                auto flagTree
                                    = use->getRegDef(X86Register::FLAGS);
                                TreeCapture capture;
                                if(ComparisonForm2::matches(
                                    flagTree, capture)) {

                                    LOG(10, "comparison in " << std::hex
                                        << use->getInstruction()->getAddress());
                                    auto boundTree = dynamic_cast<
                                        TreeNodeConstant *>(capture.get(0));
                                    if(getBoundFromCompare(use,
                                        boundTree->getValue(),
                                        info)) {

                                        found = true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    auto parser2 = [&, info](UDState *s, TreeCapture& cap) {
        LOG(10, "s = 0x" << std::hex << s->getInstruction()->getAddress());
        IF_LOG(10) s->dumpState();
        for(auto& pair : loadStates) {
            if(pair.second == MemLocation(cap.get(0))) {
                auto boundTree = dynamic_cast<TreeNodeConstant *>(cap.get(1));
                if(getBoundFromCompare(s, boundTree->getValue(), info)) {
                    LOG(10, "FOUND!");
                    found = true;
                    return true;
                }
            }
        }
        return false;
    };
    if(!found) {
        LOG(10, "checking against an argument on stack");
        ReverseReversePostorder order(info->cfg);
        for(const auto& pair : loadStates) {
            auto s = pair.first;
            order.gen(s->getNode()->getID());
            auto vec = order.get()[0];
            for(auto it = vec.begin() + 1; it != vec.end(); ++it) {
                auto block = info->cfg->get(*it)->getBlock();
                auto instr = block->getChildren()->getIterable()->getLast();
                auto s = info->working->getState(instr);
                FlowUtil::searchUpDef<ComparisonForm>(
                    s, X86Register::FLAGS, parser2);
                if(found) {
                    return true;
                }
            }
        }
    }
    return found;
}
#endif

bool JumptableDetection::getBoundFromBitTest(UDState *state, int reg,
    JumptableInfo *info) {

    LOG(10, "getBoundFromBitTest 0x"
        << std::hex << state->getInstruction()->getAddress()
        << " reg " << std::dec << reg);
    IF_LOG(10) state->dumpState();

#ifdef ARCH_X86_64
    typedef TreePatternBinary<TreeNodeAnd,
        TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>,
        TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>
    > BitTestForm;

    // the register should be the same, otherwise it must have a def tree
    bool found = false;
    auto parser = [&, info](UDState *s, TreeCapture& cap) {
        LOG(10, "s = 0x" << std::hex << s->getInstruction()->getAddress());
        IF_LOG(10) s->dumpState();
        TreeNodePhysicalRegister *regTree = nullptr;
        TreeNodePhysicalRegister *otherTree = nullptr;
        regTree = dynamic_cast<TreeNodePhysicalRegister *>(cap.get(0));
        otherTree = dynamic_cast<TreeNodePhysicalRegister *>(cap.get(1));
        if(otherTree->getRegister() == reg) {
            auto tmp = regTree;
            regTree = otherTree;
            otherTree = tmp;
        }
        if(regTree->getRegister() != reg) return false;
        LOG(10, "   should look for R" << std::dec << otherTree->getRegister());
        for(auto& s2 : s->getRegRef(otherTree->getRegister())) {
            LOG(10, "    s2 = 0x"
                << std::hex << s2->getInstruction()->getAddress());
            IF_LOG(10) s2->dumpState();
            if(auto bitTree = dynamic_cast<TreeNodeConstant *>(
                s2->getRegDef(otherTree->getRegister()))) {

                auto bits = bitTree->getValue();
                int pos = 0;
                while(bits) {
                    bits>>=1;
                    pos++;
                }
                if(getBoundFromCompare(s, pos, info)) {
                    found = true;
                    return true;
                }
            }
        }
        return false;
    };

    LOG(10, "finding bit test against " << std::dec << reg);

    ReverseReversePostorder order(info->cfg);
    order.gen(info->jumpState->getNode()->getID());
    auto vec = order.get()[0];
    for(auto it = vec.begin() + 1; it != vec.end(); ++it) {
        LOG(10, "checking " << *it);
        auto block = info->cfg->get(*it)->getBlock();
        auto instr = block->getChildren()->getIterable()->getLast();
        auto s = info->working->getState(instr);
        FlowUtil::searchUpDef<BitTestForm>(s, X86Register::FLAGS, parser);
        if(found) {
            return true;
        }
    }
#endif
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

    TreeCapture capture;
    if(IndexTableAccessForm::matches(state->getRegDef(reg), capture)) {
        LOG(5, "Dereference from index table 0x" << std::hex
            << state->getInstruction()->getAddress());
        bool found = false;

        auto parser = [&, info](UDState *s, TreeCapture& cap) {
            auto boundTree = dynamic_cast<TreeNodeConstant *>(cap.get(1));
            info->entries = boundTree->getValue() / info->scale;
            found = true;
            return true;
        };

        auto baseRegTree
            = dynamic_cast<TreeNodePhysicalRegister *>(capture.get(0));
        LOG(10, "look for reg " << baseRegTree->getRegister());
        FlowUtil::searchUpDef<MakeTableIndexForm>(
            state, baseRegTree->getRegister(), parser);
        return found;
    }
    return false;
}

bool JumptableDetection::getBoundFromArgument(UDState *state, int reg,
    JumptableInfo *info) {

#ifdef ARCH_X86_64
    typedef TreePatternBinary<TreeNodeComparison,
        TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>,
        TreePatternCapture<TreePatternTerminal<TreeNodeConstant>>
    > ComparisonForm;

    LOG(10, "getBoundFromArgument 0x"
        << std::hex << state->getInstruction()->getAddress()
        << " reg " << std::dec << reg);
    IF_LOG(10) state->dumpState();

    // the register should be the same, otherwise it must have a def tree
    bool found = false;
    auto parser = [&, info](UDState *s, TreeCapture& cap) {
        LOG(10, "s = " << std::hex << s->getInstruction()->getAddress());
        IF_LOG(10) s->dumpState();
        if(!state->getRegRef(reg).empty()) {
            bool reachable = false;
            LOG(10, "    reg has a def node");
            for(auto &ref : state->getRegRef(reg)) {
                reachable = isReachable<Preorder>(info->cfg,
                    ref->getNode()->getID(), s->getNode()->getID());
                LOG(10, "reachable? " << reachable);
                if(reachable) break;
            }
            if(!reachable) return false;
        }
        auto regTree = dynamic_cast<TreeNodePhysicalRegister *>(cap.get(0));
        if(regTree->getRegister() != reg) return false;
        LOG(10, "   modifies eflags");
        auto boundTree = dynamic_cast<TreeNodeConstant *>(cap.get(1));
        if(getBoundFromCompare(s, boundTree->getValue(), info)) {
            found = true;
            return true;
        }
        return false;
    };

    ReverseReversePostorder order(info->cfg);
    order.gen(info->jumpState->getNode()->getID());
    auto vec = order.get()[0];
    for(auto it = vec.begin() + 1; it != vec.end(); ++it) {
        LOG(10, "checking " << *it);
        auto block = info->cfg->get(*it)->getBlock();
        auto instr = block->getChildren()->getIterable()->getLast();
        auto s = info->working->getState(instr);
        FlowUtil::searchUpDef<ComparisonForm>(s, X86Register::FLAGS, parser);
        if(found) {
            return true;
        }
    }
    return false;
#elif defined(ARCH_AARCH64)
    typedef TreePatternBinary<TreeNodeComparison,
        TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>,
        TreePatternCapture<TreePatternTerminal<TreeNodeConstant>>
    > ComparisonForm;

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

    ReverseReversePostorder order(info->cfg);
    order.gen(info->jumpState->getNode()->getID());
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
#endif
}

