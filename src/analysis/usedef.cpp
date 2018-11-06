#include "usedef.h"
#include "analysis/jumptable.h"
#include "analysis/slicingtree.h"
#include "analysis/slicingmatch.h"
#include "chunk/concrete.h"
#include "disasm/dump.h"
#include "instr/assembly.h"
#include "instr/isolated.h"

#include <assert.h>
#include "chunk/dump.h"
#include "log/log.h"

void DefList::set(int reg, TreeNode *tree) {
    list[reg] = tree;
}

void DefList::del(int reg) {
    list.erase(reg);
}

TreeNode *DefList::get(int reg) const {
    auto it = list.find(reg);
    if(it != list.end()) {
        return it->second;
    }
    return nullptr;
}

void DefList::dump() const {
    for(auto d : list) {
        LOG0(1, "R" << std::dec << d.first << ":  ");
        if(auto tree = d.second) {
            IF_LOG(1) tree->print(TreePrinter(0, 0));
        }
        LOG(1, "");
    }
}


void RefList::set(int reg, UDState *origin) {
    list[reg] = {origin};
}

void RefList::add(int reg, UDState *origin) {
    auto exist = addIfExist(reg, origin);
    if(!exist) {
        list[reg].push_back(origin);
    }
}

bool RefList::addIfExist(int reg, UDState *origin) {
    bool found = false;
    auto it = list.find(reg);
    if(it != list.end()) {
        bool duplicate = false;
        for(auto s : it->second) {
            if(s == origin) {
                duplicate = true;
                break;
            }
        }
        if(!duplicate) {
            it->second.push_back(origin);
        }
        found = true;
    }
    return found;
}

void RefList::del(int reg) {
    list.erase(reg);
}

void RefList::clear() {
    list.clear();
}

const std::vector<UDState *>& RefList::get(int reg) const {
    auto it = list.find(reg);
    if(it != list.end()) {
        return it->second;
    }
    static std::vector<UDState *> emptyList;
    return emptyList;
}

void RefList::dump() const {
    for(const auto& r : list) {
        LOG0(1, "R" << std::dec << r.first << " <[");
        for(auto o : r.second) {
            LOG0(1, " 0x" << std::hex << o->getInstruction()->getAddress());
        }
        LOG(1, " ]");
    }
}

void UseList::add(int reg, UDState *state) {
    bool duplicate = false;
    auto it = list.find(reg);
    if(it != list.end()) {
        for(auto s : it->second) {
            if(s == state) {
                duplicate = true;
                break;
            }
        }
    }
    if(!duplicate) {
        list[reg].push_back(state);
    }
}

void UseList::del(int reg, UDState *state) {
    auto it = list.find(reg);
    if(it != list.end()) {
        for(auto& s : it->second) {
            if(s == state) {
                s = it->second.back();
                it->second.pop_back();
            }
        }
    }
}

const std::vector<UDState *>& UseList::get(int reg) const {
    auto it = list.find(reg);
    if(it != list.end()) {
        return it->second;
    }
    static std::vector<UDState *> emptyList;
    return emptyList;
}


void UseList::dump() const {
    for(const auto& u : list) {
        LOG0(1, "R" << std::dec << u.first << " <[");
        for(auto o : u.second) {
            LOG0(1, " 0x" << std::hex << o->getInstruction()->getAddress());
        }
        LOG(1, " ]");
    }
}


void MemOriginList::set(TreeNode *place, UDState *origin) {
    bool found = false;
    MemLocation m1(place);
    for(auto it = list.rbegin(); it != list.rend(); ++it) {
        MemLocation m2(it->place);
        if(m1 == m2) {
            if(!found) {
                found = true;
                *it = MemOrigin(place, origin);
            }
            else {
                *it = list.back();
                list.pop_back();
            }
        }
    }
    if(!found) {
        list.emplace_back(place, origin);
    }
}

void MemOriginList::add(TreeNode *place, UDState *origin) {
    bool duplicate = false;
    MemLocation m1(place);
    for(const auto& mem : list) {
        if(mem.origin == origin) {
            MemLocation m2(mem.place);
            if(m1 == m2) {
                duplicate = true;
                break;
            }
        }
    }
    if(!duplicate) {
        list.emplace_back(place, origin);
    }
}

void MemOriginList::addList(const MemOriginList& other) {
    for(const auto& m : other) {
        add(m.place, m.origin);
    }
}

void MemOriginList::del(TreeNode *tree) {
    MemLocation m1(tree);
    for(auto it = list.rbegin(); it != list.rend(); ++it) {
        MemLocation m2(it->place);
        if(m1 == m2) {
            *it = list.back();
            list.pop_back();
        }
    }
}

void MemOriginList::clear() {
    list.clear();
}

void MemOriginList::dump() const {
    for(const auto &m : list) {
        IF_LOG(1) m.place->print(TreePrinter(0, 0));
        LOG(1, " : 0x"
             << std::hex << m.origin->getInstruction()->getAddress());
    }
}

void RegState::dumpRegState() const {
    LOG(1, "reg definition list:");
    regList.dump();

    LOG(1, "reg reference list:");
    regRefList.dump();

    // this is empty for the first pass
    LOG(1, "reg use list:");
    regUseList.dump();
}

void RegMemState::dumpMemState() const {
    LOG(1, "mem definition list:");
    memList.dump();

    LOG(1, "mem reference list:");
    memRefList.dump();

    // this is empty for the first pass
    LOG(1, "mem use list:");
    memUseList.dump();
}


UDConfiguration::UDConfiguration(ControlFlowGraph *cfg,
    const std::vector<int> &idList) : cfg(cfg) {

    if(idList.size() == 0) {
        allEnabled = true;
    }
    else {
        allEnabled = false;
        for(auto id : idList) {
            enabled[id] = true;
        }
    }
}

bool UDConfiguration::isEnabled(int id) const {
    if(allEnabled) return true;

    auto it = enabled.find(id);
    if(it != enabled.end()) {
        return true;
    }
    return false;
}

void UDWorkingSet::transitionTo(ControlFlowNode *node) {
    regSet = &nodeExposedRegSetList[node->getID()];
    memSet = &nodeExposedMemSetList[node->getID()];
    regSet->clear();
    memSet->clear();
    for(auto link : node->backwardLinks()) {
        for(auto mr : nodeExposedRegSetList[link->getTargetID()]) {
            for(auto o : mr.second) {
                addToRegSet(mr.first, o);
            }
        }

        memSet->addList(nodeExposedMemSetList[link->getTargetID()]);
    }
}

void UDWorkingSet::copyFromMemSetFor(
    UDState *state, int reg, TreeNode *place) {

    MemLocation loc1(place);
    for(auto &m : *memSet) {
        MemLocation loc2(m.place);
        if(loc1 == loc2) {
            state->addMemRef(reg, m.origin);
            // register may be different
            // e.g. str x0, [x29, #16] -> ldr x1, [x29, #16]
            for(const auto& mdef : m.origin->getMemDefList()) {
                if(m.place->equal(mdef.second)) {
                    m.origin->addMemUse(mdef.first, state);
                    break;
                }
            }

        }
    }
}

void UDWorkingSet::dumpSet() const {
    LOG(10, "REG SET");
    IF_LOG(10) regSet->dump();

    LOG(10, "MEM SET");
    IF_LOG(10) memSet->dump();
}

UDRegMemWorkingSet::UDRegMemWorkingSet(
    Function *function, ControlFlowGraph *cfg, bool trackPartial)
    : UDWorkingSet(cfg, trackPartial), function(function), cfg(cfg) {

    for(auto block : CIter::children(function)) {
        auto node = cfg->get(cfg->getIDFor(block));
        for(auto instr : CIter::children(block)) {
            stateList.emplace_back(node, instr);
            stateListIndex[instr] = stateList.size() - 1;
        }
    }
}

UDState *UDRegMemWorkingSet::getState(Instruction *instruction) {
    return &stateList[stateListIndex[instruction]];
}


const std::map<int, UseDef::HandlerType> UseDef::handlers = {
#ifdef ARCH_X86_64
    {X86_INS_AND,       &UseDef::fillAnd},
    {X86_INS_ADD,       &UseDef::fillAddOrSub},
    {X86_INS_BSF,       &UseDef::fillBsf},
    {X86_INS_BT,        &UseDef::fillBt},
    {X86_INS_CALL,      &UseDef::fillCall},
    {X86_INS_CMP,       &UseDef::fillCmp},
    {X86_INS_INC,       &UseDef::fillInc},
    {X86_INS_JA,        &UseDef::fillJa},
    {X86_INS_JAE,       &UseDef::fillJae},
    {X86_INS_JB,        &UseDef::fillJb},
    {X86_INS_JBE,       &UseDef::fillJbe},
    {X86_INS_JE,        &UseDef::fillJe},
    {X86_INS_JNE,       &UseDef::fillJne},
    {X86_INS_JG,        &UseDef::fillJg},
    {X86_INS_JGE,       &UseDef::fillJge},
    {X86_INS_JL,        &UseDef::fillJl},
    {X86_INS_JLE,       &UseDef::fillJle},
    {X86_INS_JMP,       &UseDef::fillJmp},
    {X86_INS_LEA,       &UseDef::fillLea},
    {X86_INS_MOV,       &UseDef::fillMov},
    {X86_INS_MOVABS,    &UseDef::fillMovabs},
    {X86_INS_MOVSXD,    &UseDef::fillMovsxd},
    {X86_INS_MOVZX,     &UseDef::fillMovzx},
    {X86_INS_TEST,      &UseDef::fillTest},
    {X86_INS_PUSH,      &UseDef::fillPush},
    {X86_INS_SUB,       &UseDef::fillAddOrSub},
    {X86_INS_SYSCALL,   &UseDef::fillSyscall},
    {X86_INS_XOR,       &UseDef::fillXor},
#elif defined(ARCH_AARCH64)
    {ARM64_INS_ADD,     &UseDef::fillAddOrSub},
    {ARM64_INS_ADR,     &UseDef::fillAdr},
    {ARM64_INS_ADRP,    &UseDef::fillAdrp},
    {ARM64_INS_AND,     &UseDef::fillAnd},
    {ARM64_INS_B,       &UseDef::fillB},
    {ARM64_INS_BL,      &UseDef::fillBl},
    {ARM64_INS_BLR,     &UseDef::fillBlr},
    {ARM64_INS_BR,      &UseDef::fillBr},
    {ARM64_INS_CBZ,     &UseDef::fillCbz},
    {ARM64_INS_CBNZ,    &UseDef::fillCbnz},
    {ARM64_INS_CMP,     &UseDef::fillCmp},
    {ARM64_INS_CSEL,    &UseDef::fillCsel},
    {ARM64_INS_CSET,    &UseDef::fillCset},
    {ARM64_INS_EOR,     &UseDef::fillEor},
    {ARM64_INS_FMOV,    &UseDef::fillFmov},
    {ARM64_INS_LDAXR,   &UseDef::fillLdaxr},
    {ARM64_INS_LDP,     &UseDef::fillLdp},
    {ARM64_INS_LDR,     &UseDef::fillLdr},
    {ARM64_INS_LDRH,    &UseDef::fillLdrh},
    {ARM64_INS_LDRB,    &UseDef::fillLdrb},
    {ARM64_INS_LDRSW,   &UseDef::fillLdrsw},
    {ARM64_INS_LDRSH,   &UseDef::fillLdrsh},
    {ARM64_INS_LDRSB,   &UseDef::fillLdrsb},
    {ARM64_INS_LDUR,    &UseDef::fillLdur},
    {ARM64_INS_LSL,     &UseDef::fillLsl},
    {ARM64_INS_MADD,    &UseDef::fillMadd},
    {ARM64_INS_MOV,     &UseDef::fillMov},
    {ARM64_INS_MRS,     &UseDef::fillMrs},
    {ARM64_INS_NOP,     &UseDef::fillNop},
    {ARM64_INS_ORR,     &UseDef::fillOrr},
    {ARM64_INS_RET,     &UseDef::fillRet},
    {ARM64_INS_STP,     &UseDef::fillStp},
    {ARM64_INS_STR,     &UseDef::fillStr},
    {ARM64_INS_STRB,    &UseDef::fillStrb},
    {ARM64_INS_STRH,    &UseDef::fillStrh},
    {ARM64_INS_SUB,     &UseDef::fillAddOrSub},
    {ARM64_INS_SXTW,    &UseDef::fillSxtw},
    {ARM64_INS_UBFIZ,   &UseDef::fillUbfiz},
#elif defined(ARCH_RISCV)
    {rv_op_add,         &UseDef::fillRegRegToReg},
    {rv_op_addi,        &UseDef::fillRegImmToReg},
    {rv_op_and,         &UseDef::fillRegRegToReg},
    {rv_op_andi,        &UseDef::fillRegImmToReg},
    {rv_op_auipc,       &UseDef::fillImmToReg},
    {rv_op_beq,         &UseDef::fillB},
    {rv_op_beqz,        &UseDef::fillB},
    {rv_op_bgtu,        &UseDef::fillB},
    {rv_op_bne,         &UseDef::fillB},
    {rv_op_bnez,        &UseDef::fillB},
    {rv_op_j,           &UseDef::fillJ},
    {rv_op_jal,         &UseDef::fillJal},
    {rv_op_jalr,        &UseDef::fillJalr},
    {rv_op_jr,          &UseDef::fillJr},
    {rv_op_lb,          &UseDef::fillLoad},
    {rv_op_lbu,         &UseDef::fillLoad},
    {rv_op_lh,          &UseDef::fillLoad},
    {rv_op_lhu,         &UseDef::fillLoad},
    {rv_op_ld,          &UseDef::fillLoad},
    {rv_op_lw,          &UseDef::fillLoad},
    {rv_op_lwu,         &UseDef::fillLoad},
    {rv_op_lui,         &UseDef::fillImmToReg},
    {rv_op_mv,          &UseDef::fillRegToReg},
    {rv_op_ret,         &UseDef::fillRet},
    {rv_op_sb,          &UseDef::fillStore},
    {rv_op_sd,          &UseDef::fillStore},
    {rv_op_slli,        &UseDef::fillRegImmToReg},
    {rv_op_srai,        &UseDef::fillRegImmToReg},
    {rv_op_srli,        &UseDef::fillRegImmToReg},
    {rv_op_sub,         &UseDef::fillRegRegToReg},
#endif
};

void UseDef::analyze(const std::vector<std::vector<int>>& order) {
    LOG(10, "full order:");
    for(auto o : order) {
        LOG0(10, "{");
        for(auto n : o) {
            LOG0(10, " " << std::dec << n);
        }
        LOG0(10, " }");
    }
    LOG(10, "");

    for(auto o : order) {
        analyzeGraph(o);
        if(o.size() > 1) {
            analyzeGraph(o);
        }
    }
}

void UseDef::analyzeGraph(const std::vector<int>& order) {
    LOG(10, "order:");
    for(auto o : order) {
        LOG0(10, " " << std::dec << o);
    }
    LOG(10, "");

    for(auto nodeId : order) {
        auto node = config->getCFG()->get(nodeId);
        working->transitionTo(node);

        auto blockList = CIter::children(node->getBlock());

        for(auto it = blockList.begin(); it != blockList.end(); ++it) {
            auto state = working->getState(*it);

            LOG(10, "analyzing state @ 0x" << std::hex
                << state->getInstruction()->getAddress());

            if(dynamic_cast<LiteralInstruction *>(
                state->getInstruction()->getSemantic())) {
                continue;
            }

            fillState(state);
        }

        LOG(11, "");
        LOG(11, "final set for node " << std::dec << nodeId);
        IF_LOG(11) working->dumpSet();
        LOG(11, "");
    }
}

bool UseDef::callIfEnabled(UDState *state, Instruction *instruction) {
#ifdef ARCH_X86_64
    #define INVALID_ID  X86_INS_INVALID
#elif defined(ARCH_AARCH64)
    #define INVALID_ID  ARM64_INS_INVALID
#elif defined(ARCH_RISCV)
    #define INVALID_ID rv_op_illegal
#endif
    AssemblyPtr assembly = instruction->getSemantic()->getAssembly();
    int id = INVALID_ID;
    if(assembly) {
        id = assembly->getId();
    }
    else {
#ifdef ARCH_X86_64
        auto v = dynamic_cast<ControlFlowInstruction *>(
            instruction->getSemantic());
        if(v) id = v->getId();
#else
        LOG(1, __func__ << ": how do we gent id?");
#endif
    }

    bool handled = false;
    if(config->isEnabled(id)) {
        auto it = handlers.find(id);
        if(it != handlers.end()) {
            auto f = it->second;
            (this->*f)(state, assembly);
            handled = true;
        }
    }
    if(!handled) {
        LOG0(10, "handler disabled (or not found)");
        LOG(1, "mnemonic not implemented: " << assembly->getMnemonic());
        assert(0);
        if(assembly) {
            LOG(10, " " << assembly->getMnemonic());
            LOG(10, "mode: " << assembly->getAsmOperands()->getMode());
        }
        else {
            LOG(10, " -- no assembly");
        }
    }

    return handled;
}

void UseDef::fillState(UDState *state) {
    ChunkDumper dumper;
    IF_LOG(11) state->getInstruction()->accept(&dumper);

    bool handled = callIfEnabled(state, state->getInstruction());
    if(handled) {
        IF_LOG(11) state->dumpState();
        IF_LOG(11) working->dumpSet();
    }
}

void UseDef::defReg(UDState *state, int reg, TreeNode *tree) {
#ifdef ARCH_X86_64
    if(!X86Register::isInteger(reg) && reg != X86Register::FLAGS) {
        LOG(0, "reg = " << std::dec << reg
            << std::hex << " at " << state->getInstruction()->getAddress());
        throw "error defReg";
    }
#endif
    if(reg != -1) {
        state->addRegDef(reg, tree);
        working->setAsRegSet(reg, state);
    }
}

void UseDef::useReg(UDState *state, int reg) {
#ifdef ARCH_X86_64
    if(!X86Register::isInteger(reg) && reg != X86Register::FLAGS) {
        LOG(0, "reg = " << std::dec << reg
            << std::hex << " at " << state->getInstruction()->getAddress());
        throw "error useReg";
    }
#endif

    if(working->getRegSet(reg).empty()
        && working->shouldTrackPartialUDChains()) {

        defReg(state, reg, new TreeNodeRegister(reg));
    }
    else {
        for(auto o : working->getRegSet(reg)) {
            state->addRegRef(reg, o);
            o->addRegUse(reg, state);
        }
    }
}

void UseDef::cancelUseDefReg(UDState *state, int reg) {
    for(auto o : state->getRegRef(reg)) {
        o->delRegUse(reg, state);
        for(auto u : state->getRegUse(reg)) {
            o->addRegUse(reg, u);
            u->addRegRef(reg, o);
        }
    }
    state->delRegDef(reg);
    state->delRegRef(reg);
}

void UseDef::defMem(UDState *state, TreeNode *place, int reg) {
#ifdef ARCH_X86_64
    if(!X86Register::isInteger(reg) && reg != X86Register::FLAGS) {
        LOG(0, "reg = " << std::dec << reg
            << std::hex << " at " << state->getInstruction()->getAddress());
        throw "error defMem";
    }
#endif
    state->addMemDef(reg, place);
    working->setAsMemSet(place, state);
}

void UseDef::useMem(UDState *state, TreeNode *place, int reg) {
#ifdef ARCH_X86_64
    if(!X86Register::isInteger(reg) && reg != X86Register::FLAGS) {
        LOG(0, "reg = " << std::dec << reg
            << std::hex << " at " << state->getInstruction()->getAddress());
        throw "error useMem";
    }
#endif
    working->copyFromMemSetFor(state, reg, place);
}

TreeNode *UseDef::shiftExtend(TreeNode *tree, arm64_shifter type,
    unsigned int value) {

    switch(type) {
    case ARM64_SFT_LSL:
        tree = TreeFactory::instance().make<TreeNodeLogicalShiftLeft>(tree,
            TreeFactory::instance().make<TreeNodeConstant>(value));
        break;
    case ARM64_SFT_MSL:
        throw "msl";
        break;
    case ARM64_SFT_LSR:
        tree = TreeFactory::instance().make<TreeNodeLogicalShiftRight>(tree,
            TreeFactory::instance().make<TreeNodeConstant>(value));
        break;
    case ARM64_SFT_ASR:
        tree = TreeFactory::instance().make<TreeNodeArithmeticShiftRight>(tree,
            TreeFactory::instance().make<TreeNodeConstant>(value));
        break;
    case ARM64_SFT_ROR:
        tree = TreeFactory::instance().make<TreeNodeRotateRight>(tree,
            TreeFactory::instance().make<TreeNodeConstant>(value));
        break;
    case ARM64_SFT_INVALID:
    default:
        break;
    }

    return tree;
}

void UseDef::fillImm(UDState *state, AssemblyPtr assembly) {
    throw "NYI: fillImm";
}

void UseDef::fillReg(UDState *state, AssemblyPtr assembly) {
#ifdef ARCH_AARCH64
    auto op0 = assembly->getAsmOperands()->getOperands()[0].reg;
    int reg0 = AARCH64GPRegister::convertToPhysical(op0);
    useReg(state, reg0);
#endif
}

void UseDef::fillRegToReg(UDState *state, AssemblyPtr assembly) {
#ifdef ARCH_X86_64
    int reg0, reg1;
    size_t width0, width1;
    std::tie(reg0, width0)
        = getPhysicalRegister(assembly->getAsmOperands()->getOperands()[0].reg);
    std::tie(reg1, width1)
        = getPhysicalRegister(assembly->getAsmOperands()->getOperands()[1].reg);
    if(reg0 < 0 || reg1 < 0) return;  // unsupported (likely kernelspace) reg
    useReg(state, reg0);
    TreeNode *tree = nullptr;
    auto id = assembly->getId();
    if(id == X86_INS_ADD) {
        useReg(state, reg1);
        auto reg0Tree = TreeFactory::instance().make<TreeNodePhysicalRegister>(
            reg0, width0);
        auto reg1Tree = TreeFactory::instance().make<TreeNodePhysicalRegister>(
            reg1, width1);
        tree = TreeFactory::instance().make<TreeNodeAddition>(
            reg1Tree, reg0Tree);
    } else if(id == X86_INS_SUB) {
        useReg(state, reg1);
        auto reg0Tree = TreeFactory::instance().make<TreeNodePhysicalRegister>(
            reg0, width0);
        auto reg1Tree = TreeFactory::instance().make<TreeNodePhysicalRegister>(
            reg1, width1);
        tree = TreeFactory::instance().make<TreeNodeSubtraction>(
            reg1Tree, reg0Tree);
    } else if(id == X86_INS_MOV
        || id == X86_INS_MOVSXD
        || id == X86_INS_MOVZX) {

        tree = TreeFactory::instance().make<TreeNodePhysicalRegister>(
            reg0, width0);
    }
    defReg(state, reg1, tree);
#elif defined(ARCH_AARCH64)
    auto op0 = assembly->getAsmOperands()->getOperands()[0].reg;
    int reg0 = AARCH64GPRegister::convertToPhysical(op0);
    auto op1 = assembly->getAsmOperands()->getOperands()[1].reg;
    int reg1 = AARCH64GPRegister::convertToPhysical(op1);
    size_t width1 = AARCH64GPRegister::getWidth(reg1, op1);

    useReg(state, reg1);
    auto tree = TreeFactory::instance().make<
        TreeNodePhysicalRegister>(reg1, width1);

    defReg(state, reg0, tree);
#elif defined(ARCH_RISCV)
    auto rd = assembly->getAsmOperands()->getOperands()[0].value.reg;
    auto rs = assembly->getAsmOperands()->getOperands()[1].value.reg;

    useReg(state, rs);

    TreeNode *tree = nullptr;
    switch(assembly->getId()) {
    case rv_op_mv:
        tree = TreeFactory::instance().make<TreeNodePhysicalRegister>(rs, 8);
        break;
    default:
        LOG(1, "Unhandled instruction " << assembly->getMnemonic());
        assert(0);
        break;
    }
    defReg(state, rd, tree);
#endif
}

void UseDef::fillMemToReg(UDState *state, AssemblyPtr assembly, size_t width) {
#ifdef ARCH_X86_64
    auto mem = assembly->getAsmOperands()->getOperands()[0].mem;
    int reg1;
    size_t width1;
    std::tie(reg1, width1) = getPhysicalRegister(
        assembly->getAsmOperands()->getOperands()[1].reg);

    if(mem.segment != INVALID_REGISTER) {
        defReg(state, reg1, nullptr);
        return;
    }
    TreeNode *tree = nullptr;
    auto memTree = makeMemTree(state, mem);
    auto id = assembly->getId();
    if(id == X86_INS_ADD) {
        useMem(state, memTree, reg1);
        tree = TreeFactory::instance().make<TreeNodeDereference>(
            memTree, width);

        useReg(state, reg1);
        auto reg1Tree = TreeFactory::instance().make<TreeNodePhysicalRegister>(
            reg1, width1);
        tree = TreeFactory::instance().make<TreeNodeAddition>(
            reg1Tree, tree);
    }
    else if(id == X86_INS_LEA) {
        tree = memTree;
    }
    else if(id == X86_INS_MOV
        || id == X86_INS_MOVSXD
        || id == X86_INS_MOVZX) {

        if(memTree) {
            useMem(state, memTree, reg1);
            tree = TreeFactory::instance().make<TreeNodeDereference>(
                memTree, width);
        }
        else {
            tree = TreeFactory::instance().make<TreeNodeConstant>(0);
        }
    }
    defReg(state, reg1, tree);
#elif defined(ARCH_AARCH64)
    assert(!assembly->isPostIndex());

    auto op0 = assembly->getAsmOperands()->getOperands()[0].reg;
    int reg0 = AARCH64GPRegister::convertToPhysical(op0);

    auto mem = assembly->getAsmOperands()->getOperands()[1].mem;
    auto base = AARCH64GPRegister::convertToPhysical(mem.base);
    size_t widthB = AARCH64GPRegister::getWidth(base, mem.base);
    useReg(state, base);

    auto baseTree
        = TreeFactory::instance().make<TreeNodePhysicalRegister>(base, widthB);
    TreeNode *memTree = nullptr;
    if(mem.index != INVALID_REGISTER) {
        auto regI = AARCH64GPRegister::convertToPhysical(mem.index);
        size_t widthI = AARCH64GPRegister::getWidth(regI, mem.index);
        useReg(state, regI);

        TreeNode *indexTree = TreeFactory::instance().make<
            TreeNodePhysicalRegister>(regI, widthI);
        auto shift = assembly->getAsmOperands()->getOperands()[1].shift;
        indexTree = shiftExtend(indexTree, shift.type, shift.value);
        memTree = TreeFactory::instance().make<TreeNodeAddition>(
            baseTree,
            indexTree);
    }
    else {
        memTree = TreeFactory::instance().make<TreeNodeAddition>(
            baseTree,
            TreeFactory::instance().make<TreeNodeConstant>(mem.disp));

        if(assembly->isPreIndex()) {
            defReg(state, base, memTree);
        }
    }
    useMem(state, memTree, reg0);

    auto derefTree
        = TreeFactory::instance().make<TreeNodeDereference>(memTree, width);
    defReg(state, reg0, derefTree);
#elif defined(ARCH_RISCV)
    auto rd = assembly->getAsmOperands()->getOperands()[0].value.reg;
    auto mem = assembly->getAsmOperands()->getOperands()[1].value.mem;

    useReg(state, mem.basereg);

    auto rs1tree =
        TreeFactory::instance().make<TreeNodePhysicalRegister>(mem.basereg, 8);

    auto memTree = TreeFactory::instance().make<TreeNodeAddition>(
        rs1tree,
        TreeFactory::instance().make<TreeNodeConstant>(mem.disp));

    // int width = 0;
    switch(assembly->getId()) {
    case rv_op_lb:
    case rv_op_lbu:
        width = 1;
        break;
    case rv_op_lh:
    case rv_op_lhu:
        width = 2;
        break;
    case rv_op_lw:
    case rv_op_lwu:
        width = 4;
        break;
    case rv_op_ld:
        width = 8;
        break;
    }

    useMem(state, memTree, width);
    defReg(state, rd,
        TreeFactory::instance().make<TreeNodeDereference>(memTree, width));
#endif
}

void UseDef::fillImmToReg(UDState *state, AssemblyPtr assembly) {
#ifdef ARCH_X86_64
    auto op0 = assembly->getAsmOperands()->getOperands()[0].imm;
    auto op1 = assembly->getAsmOperands()->getOperands()[1].reg;

    int reg1;
    size_t width1;
    std::tie(reg1, width1) = getPhysicalRegister(op1);
    auto tree1 = TreeFactory::instance().make<TreeNodePhysicalRegister>(
        reg1, width1);
    auto tree0 = TreeFactory::instance().make<TreeNodeConstant>(op0);
    if(assembly->getId() == X86_INS_ADD) {
        auto destTree
            = TreeFactory::instance().make<TreeNodeAddition>(tree1, tree0);
        useReg(state, reg1);
        defReg(state, reg1, destTree);
    }
    else if(assembly->getId() == X86_INS_SUB) {
        auto destTree
            = TreeFactory::instance().make<TreeNodeSubtraction>(tree1, tree0);
        useReg(state, reg1);
        defReg(state, reg1, destTree);
    }
    else if(assembly->getId() == X86_INS_MOV) {
        defReg(state, reg1, tree0);
    }
    else if(assembly->getId() == X86_INS_MOVABS) {
        defReg(state, reg1, tree0);
    }
    else if(assembly->getId() == X86_INS_AND) {
        auto destTree = TreeFactory::instance().make<TreeNodeAnd>(tree1, tree0);
        useReg(state, reg1);
        defReg(state, reg1, destTree);
    }
    else {
        throw "error: fillImmToReg";
    }
#elif defined(ARCH_AARCH64)
    auto op0 = assembly->getAsmOperands()->getOperands()[0].reg;
    int reg0 = AARCH64GPRegister::convertToPhysical(op0);

    auto op1 = assembly->getAsmOperands()->getOperands()[1].imm;
    TreeNode *tree1 = nullptr;
    if(assembly->getId() == ARM64_INS_ADR
        || assembly->getId() == ARM64_INS_ADRP
        || assembly->getId() == ARM64_INS_LDR) {

        tree1 = TreeFactory::instance().make<TreeNodeAddress>(op1);
    }
    else {
        tree1 = TreeFactory::instance().make<TreeNodeConstant>(op1);
    }
    defReg(state, reg0, tree1);
#elif defined(ARCH_RISCV)
    auto rd = assembly->getAsmOperands()->getOperands()[0].value.reg;
    auto imm = assembly->getAsmOperands()->getOperands()[1].value.imm;
    
    TreeNode *tree = nullptr;
    switch(assembly->getId()) {
    case rv_op_lui:
        tree = TreeFactory::instance().make<TreeNodeConstant>(
            (int64_t)(imm << 12));
      break;
    case rv_op_c_lui:
        tree = TreeFactory::instance().make<TreeNodeConstant>(
            (int64_t)(imm << 12));
        break;
    case rv_op_auipc:
        // Capstone includes ip in the imm for e.g. adrp
        // but our riscv disas doesn't, so we need to add it manually
        // the disas does, however, pre-shift the imm by 12.
        uint64_t ip = state->getInstruction()->getAddress();
        tree = TreeFactory::instance().make<TreeNodeAddress>(
                ip + (int64_t)(imm));
        break;
    }
    defReg(state, rd, tree);
#endif
}

void UseDef::fillRegRegToReg(UDState *state, AssemblyPtr assembly) {
#ifdef ARCH_AARCH64
    auto op0 = assembly->getAsmOperands()->getOperands()[0].reg;
    int reg0 = AARCH64GPRegister::convertToPhysical(op0);
    auto op1 = assembly->getAsmOperands()->getOperands()[1].reg;
    int reg1 = AARCH64GPRegister::convertToPhysical(op1);
    size_t width1 = AARCH64GPRegister::getWidth(reg1, op1);
    auto op2 = assembly->getAsmOperands()->getOperands()[2].reg;
    int reg2 = AARCH64GPRegister::convertToPhysical(op2);
    size_t width2 = AARCH64GPRegister::getWidth(reg2, op2);

    useReg(state, reg1);
    useReg(state, reg2);

    TreeNode *reg1tree
        = TreeFactory::instance().make<TreeNodePhysicalRegister>(reg1, width1);
    TreeNode *reg2tree
        = TreeFactory::instance().make<TreeNodePhysicalRegister>(reg2, width2);

    auto shift = assembly->getAsmOperands()->getOperands()[2].shift;
    reg2tree = shiftExtend(reg2tree, shift.type, shift.value);

    TreeNode *tree = nullptr;
    switch(assembly->getId()) {
    case ARM64_INS_ADD:
        tree = TreeFactory::instance().make<
            TreeNodeAddition>(reg1tree, reg2tree);
        break;
    case ARM64_INS_AND:
        tree = TreeFactory::instance().make<
            TreeNodeAnd>(reg1tree, reg2tree);
        break;
    case ARM64_INS_SUB:
        tree = TreeFactory::instance().make<
            TreeNodeSubtraction>(reg1tree, reg2tree);
        break;
    default:
        tree = nullptr;
        LOG(10, "NYI: " << assembly->getMnemonic());
        break;
    }
    defReg(state, reg0, tree);
#elif defined(ARCH_RISCV)
    auto rd = assembly->getAsmOperands()->getOperands()[0].value.reg;
    auto rs1 = assembly->getAsmOperands()->getOperands()[1].value.reg;
    auto rs2 = assembly->getAsmOperands()->getOperands()[2].value.reg;

    useReg(state, rs1);
    useReg(state, rs2);

    TreeNode *reg1tree = nullptr, *reg2tree = nullptr;
    auto helper = [&](size_t width) {
        reg1tree = TreeFactory::instance().make<TreeNodePhysicalRegister>(rs1,
            width);
        reg2tree = TreeFactory::instance().make<TreeNodePhysicalRegister>(rs2,
            width);
    };

    TreeNode *tree = nullptr;
    switch(assembly->getId()) {
    case rv_op_add:
        helper(8);
        tree = TreeFactory::instance().make<
            TreeNodeAddition>(reg1tree, reg2tree);
        break;
    case rv_op_and:
        helper(8);
        tree = TreeFactory::instance().make<
            TreeNodeAnd>(reg1tree, reg2tree);
        break;
    case rv_op_sub:
        helper(8);
        tree = TreeFactory::instance().make<
            TreeNodeSubtraction>(reg1tree, reg2tree);
        break;
    default:
        LOG(1, "NYI: " << assembly->getMnemonic());
        break;
    }

    defReg(state, rd, tree);
#endif
}

void UseDef::fillMemImmToReg(UDState *state, AssemblyPtr assembly) {
#ifdef ARCH_AARCH64
    assert(assembly->isPostIndex());

    auto op0 = assembly->getAsmOperands()->getOperands()[0].reg;
    int reg0 = AARCH64GPRegister::convertToPhysical(op0);

    auto mem = assembly->getAsmOperands()->getOperands()[1].mem;
    auto base = AARCH64GPRegister::convertToPhysical(mem.base);
    size_t widthB = AARCH64GPRegister::getWidth(base, mem.base);
    useReg(state, base);

    auto baseTree
        = TreeFactory::instance().make<TreeNodePhysicalRegister>(base, widthB);

    assert(mem.index == INVALID_REGISTER);
    assert(mem.disp == 0);

    size_t width = (assembly->getBytes()[3] & 0b01000000) ? 8 : 4;
    auto memTree = TreeFactory::instance().make<TreeNodeAddition>(
        baseTree,
        TreeFactory::instance().make<TreeNodeConstant>(0));
    useMem(state, memTree, reg0);

    auto derefTree
        = TreeFactory::instance().make<TreeNodeDereference>(memTree, width);
    defReg(state, reg0, derefTree);

    auto imm = assembly->getAsmOperands()->getOperands()[2].imm;
    auto wbTree = TreeFactory::instance().make<TreeNodeAddition>(
        baseTree,
        TreeFactory::instance().make<TreeNodeConstant>(imm));
    defReg(state, base, wbTree);
#endif
}

void UseDef::fillRegToMem(UDState *state, AssemblyPtr assembly, size_t width) {
#ifdef ARCH_X86_64
    auto op0 = assembly->getAsmOperands()->getOperands()[0].reg;
    int reg0;
    std::tie(reg0, std::ignore) = getPhysicalRegister(op0);
    useReg(state, reg0);

    auto count = assembly->getAsmOperands()->getOpCount();
    if(count == 1) {    // push
        int rsp;
        size_t widthRsp;
        std::tie(rsp, widthRsp) = getPhysicalRegister(X86_REG_RSP);
        auto rspTree = TreeFactory::instance().make<TreeNodePhysicalRegister>(
            rsp, widthRsp);
        useReg(state, rsp);
        auto memTree = TreeFactory::instance().make<TreeNodeSubtraction>(
            rspTree, TreeFactory::instance().make<TreeNodeConstant>(8));
        defReg(state, rsp, memTree);
        defMem(state, memTree, reg0);
    }
    else {  // movl
        auto memTree = makeMemTree(state,
            assembly->getAsmOperands()->getOperands()[1].mem);
        if(!memTree) {
            memTree = TreeFactory::instance().make<TreeNodeConstant>(0);
        }
        defMem(state, memTree, reg0);
    }

#elif defined(ARCH_AARCH64)
    assert(!assembly->isPostIndex());

    auto op0 = assembly->getAsmOperands()->getOperands()[0].reg;
    int reg0 = AARCH64GPRegister::convertToPhysical(op0);
    useReg(state, reg0);

    auto mem = assembly->getAsmOperands()->getOperands()[1].mem;
    auto base = AARCH64GPRegister::convertToPhysical(mem.base);
    size_t widthB = AARCH64GPRegister::getWidth(base, mem.base);
    useReg(state, base);

    auto baseTree
        = TreeFactory::instance().make<TreeNodePhysicalRegister>(base, widthB);
    TreeNode *memTree = nullptr;
    if(mem.index != INVALID_REGISTER) {
        auto regI = AARCH64GPRegister::convertToPhysical(mem.index);
        size_t widthI = AARCH64GPRegister::getWidth(regI, mem.index);
        useReg(state, regI);

        TreeNode *indexTree = TreeFactory::instance().make<
            TreeNodePhysicalRegister>(regI, widthI);
        auto shift = assembly->getAsmOperands()->getOperands()[1].shift;
        indexTree = shiftExtend(indexTree, shift.type, shift.value);
        memTree = TreeFactory::instance().make<TreeNodeAddition>(
            baseTree,
            indexTree);
    }
    else {
        memTree = TreeFactory::instance().make<TreeNodeAddition>(
            baseTree,
            TreeFactory::instance().make<TreeNodeConstant>(mem.disp));

        if(assembly->isPreIndex()) {
            defReg(state, base, memTree);
        }
    }

    defMem(state, memTree, reg0);
#elif defined(ARCH_RISCV)
    auto rs2 = assembly->getAsmOperands()->getOperands()[0].value.reg;
    auto mem = assembly->getAsmOperands()->getOperands()[1].value.mem;

    useReg(state, rs2);
    useReg(state, mem.basereg);

    auto rs1tree =
        TreeFactory::instance().make<TreeNodePhysicalRegister>(mem.basereg, 8);

    TreeNode *memTree = rs1tree;
    if(mem.disp != 0) {
        memTree = TreeFactory::instance().make<TreeNodeAddition>(
            rs1tree,
            TreeFactory::instance().make<TreeNodeConstant>(mem.disp));
    }

    // int width = 0;
    switch(assembly->getId()) {
    case rv_op_sb:
        width = 1;
        break;
    case rv_op_sh:
        width = 2;
        break;
    case rv_op_sw:
        width = 4;
        break;
    case rv_op_sd:
        width = 8;
        break;
    }

    LOG(1, "XXX: width of store not specified!");

    defMem(state, memTree, rs2);
#endif
}

void UseDef::fillRegImmToReg(UDState *state, AssemblyPtr assembly) {
#ifdef ARCH_AARCH64
    auto op0 = assembly->getAsmOperands()->getOperands()[0].reg;
    int reg0 = AARCH64GPRegister::convertToPhysical(op0);

    auto op1 = assembly->getAsmOperands()->getOperands()[1].reg;
    int reg1 = AARCH64GPRegister::convertToPhysical(op1);
    size_t width1 = AARCH64GPRegister::getWidth(reg1, op1);
    useReg(state, reg1);

    auto regTree
        = TreeFactory::instance().make<TreeNodePhysicalRegister>(reg1, width1);

    long int imm = assembly->getAsmOperands()->getOperands()[2].imm;
    auto shift = assembly->getAsmOperands()->getOperands()[2].shift;
    TreeNode *immTree
        = TreeFactory::instance().make<TreeNodeConstant>(imm);

    immTree = shiftExtend(immTree, shift.type, shift.value);

    TreeNode *tree = nullptr;
    switch(assembly->getId()) {
    case ARM64_INS_ADD:
        tree = TreeFactory::instance().make<
            TreeNodeAddition>(regTree, immTree);
        break;
    case ARM64_INS_AND:
        tree = TreeFactory::instance().make<
            TreeNodeAnd>(regTree, immTree);
        break;
    case ARM64_INS_SUB:
        tree = TreeFactory::instance().make<
            TreeNodeSubtraction>(regTree, immTree);
        break;
    default:
        tree = nullptr;
        LOG(10, "NYI: " << assembly->getMnemonic());
        break;
    }
    defReg(state, reg0, tree);
#elif defined(ARCH_RISCV)
    auto rd = assembly->getAsmOperands()->getOperands()[0].value.reg;
    auto rs1 = assembly->getAsmOperands()->getOperands()[1].value.reg;
    auto imm = assembly->getAsmOperands()->getOperands()[2].value.imm;

    useReg(state, rs1);

    TreeNode *reg1tree = nullptr, *immtree = nullptr;
    auto helper = [&](size_t width) {
        reg1tree = TreeFactory::instance().make<TreeNodePhysicalRegister>(rs1,
            width);
        immtree = TreeFactory::instance().make<TreeNodeConstant>(imm);
    };

    TreeNode *tree = nullptr;
    switch(assembly->getId()) {
    case rv_op_addi:
        helper(8);
        tree = TreeFactory::instance().make<TreeNodeAddition>(
            reg1tree, immtree);
        break;
    case rv_op_addiw:
        helper(4);
        tree = TreeFactory::instance().make<TreeNodeAddition>(
            reg1tree, immtree);
        break;
    case rv_op_andi:
        helper(8);
        tree = TreeFactory::instance().make<TreeNodeAnd>(
            reg1tree, immtree);
        break;
    case rv_op_slli:
        helper(8);
        tree = TreeFactory::instance().make<TreeNodeLogicalShiftLeft>(
            reg1tree, immtree);
        break;
    case rv_op_srai:
        helper(8);
        tree = TreeFactory::instance().make<TreeNodeArithmeticShiftRight>(
            reg1tree, immtree);
        break;
    case rv_op_srli:
        helper(8);
        tree = TreeFactory::instance().make<TreeNodeLogicalShiftRight>(
            reg1tree, immtree);
        break;
    default:
        LOG(1, "Mnemonic " << assembly->getMnemonic() << " NYI");
        assert(0);
    }
    defReg(state, rd, tree);
#endif
}

void UseDef::fillMemToRegReg(UDState *state, AssemblyPtr assembly) {
#ifdef ARCH_AARCH64
    assert(!assembly->isPostIndex());

    auto op0 = assembly->getAsmOperands()->getOperands()[0].reg;
    int reg0 = AARCH64GPRegister::convertToPhysical(op0);

    auto op1 = assembly->getAsmOperands()->getOperands()[1].reg;
    int reg1 = AARCH64GPRegister::convertToPhysical(op1);

    auto mem = assembly->getAsmOperands()->getOperands()[2].mem;
    auto base = AARCH64GPRegister::convertToPhysical(mem.base);
    size_t widthB = AARCH64GPRegister::getWidth(base, mem.base);
    useReg(state, base);

    assert(mem.index == INVALID_REGISTER);
    auto disp = mem.disp;
    auto dispTree = TreeFactory::instance().make<TreeNodeConstant>(disp);

    auto memTree = TreeFactory::instance().make<TreeNodeAddition>(
        TreeFactory::instance().make<TreeNodePhysicalRegister>(base, widthB),
        dispTree);
    if(assembly->isPreIndex()) {
        defReg(state, base, memTree);
    }

    size_t width = (assembly->getBytes()[3] & 0b10000000) ? 8 : 4;
    auto memTree0 = TreeFactory::instance().make<TreeNodeAddition>(
        memTree,
        TreeFactory::instance().make<TreeNodeConstant>(0));
    auto memTree1 = TreeFactory::instance().make<TreeNodeAddition>(
        memTree,
        TreeFactory::instance().make<TreeNodeConstant>(width));
    useMem(state, memTree0, reg0);
    useMem(state, memTree1, reg1);

    auto derefTree0
        = TreeFactory::instance().make<TreeNodeDereference>(memTree0, width);
    auto derefTree1
        = TreeFactory::instance().make<TreeNodeDereference>(memTree1, width);
    defReg(state, reg0, derefTree0);
    defReg(state, reg1, derefTree1);
#endif
}

void UseDef::fillRegRegToMem(UDState *state, AssemblyPtr assembly) {
#ifdef ARCH_AARCH64
    assert(!assembly->isPostIndex());

    auto op0 = assembly->getAsmOperands()->getOperands()[0].reg;
    int reg0 = AARCH64GPRegister::convertToPhysical(op0);
    auto op1 = assembly->getAsmOperands()->getOperands()[1].reg;
    int reg1 = AARCH64GPRegister::convertToPhysical(op1);

    useReg(state, reg0);
    useReg(state, reg1);

    auto mem = assembly->getAsmOperands()->getOperands()[2].mem;
    auto base = AARCH64GPRegister::convertToPhysical(mem.base);
    size_t widthB = AARCH64GPRegister::getWidth(base, mem.base);
    useReg(state, base);
    assert(mem.index == INVALID_REGISTER);
    auto disp = mem.disp;
    auto dispTree = TreeFactory::instance().make<TreeNodeConstant>(disp);

    auto memTree = TreeFactory::instance().make<TreeNodeAddition>(
        TreeFactory::instance().make<TreeNodePhysicalRegister>(base, widthB),
        dispTree);
    if(assembly->isPreIndex()) {
        defReg(state, base, memTree);
    }

    size_t width = (assembly->getBytes()[3] & 0b10000000) ? 8 : 4;
    auto memTree0 = TreeFactory::instance().make<TreeNodeAddition>(
        memTree,
        TreeFactory::instance().make<TreeNodeConstant>(0));
    auto memTree1 = TreeFactory::instance().make<TreeNodeAddition>(
        memTree,
        TreeFactory::instance().make<TreeNodeConstant>(width));

    defMem(state, memTree0, reg0);
    defMem(state, memTree1, reg1);
#endif
}

void UseDef::fillRegRegImmToMem(UDState *state, AssemblyPtr assembly) {
#ifdef ARCH_AARCH64
    assert(assembly->isPostIndex());

    auto op0 = assembly->getAsmOperands()->getOperands()[0].reg;
    int reg0 = AARCH64GPRegister::convertToPhysical(op0);
    auto op1 = assembly->getAsmOperands()->getOperands()[1].reg;
    int reg1 = AARCH64GPRegister::convertToPhysical(op1);
    useReg(state, reg0);
    useReg(state, reg1);

    auto mem = assembly->getAsmOperands()->getOperands()[2].mem;
    auto base = AARCH64GPRegister::convertToPhysical(mem.base);
    size_t widthB = AARCH64GPRegister::getWidth(base, mem.base);
    useReg(state, base);

    auto baseTree
        = TreeFactory::instance().make<TreeNodePhysicalRegister>(base, widthB);

    assert(mem.index == INVALID_REGISTER);
    assert(mem.disp == 0);

    size_t width = (assembly->getBytes()[3] & 0b10000000) ? 8 : 4;
    auto memTree0 = TreeFactory::instance().make<TreeNodeAddition>(
        baseTree,
        TreeFactory::instance().make<TreeNodeConstant>(0));
    auto memTree1 = TreeFactory::instance().make<TreeNodeAddition>(
        baseTree,
        TreeFactory::instance().make<TreeNodeConstant>(width));
    defMem(state, memTree0, reg0);
    defMem(state, memTree1, reg1);

    auto imm = assembly->getAsmOperands()->getOperands()[3].imm;
    auto wbTree = TreeFactory::instance().make<TreeNodeAddition>(
        baseTree,
        TreeFactory::instance().make<TreeNodeConstant>(imm));
    defReg(state, base, wbTree);
#endif
}

void UseDef::fillMemImmToRegReg(UDState *state, AssemblyPtr assembly) {
#ifdef ARCH_AARCH64
    assert(assembly->isPostIndex());

    auto op0 = assembly->getAsmOperands()->getOperands()[0].reg;
    int reg0 = AARCH64GPRegister::convertToPhysical(op0);
    auto op1 = assembly->getAsmOperands()->getOperands()[1].reg;
    int reg1 = AARCH64GPRegister::convertToPhysical(op1);

    auto mem = assembly->getAsmOperands()->getOperands()[2].mem;
    auto base = AARCH64GPRegister::convertToPhysical(mem.base);
    size_t widthB = AARCH64GPRegister::getWidth(base, mem.base);
    useReg(state, base);

    auto baseTree
        = TreeFactory::instance().make<TreeNodePhysicalRegister>(base, widthB);

    assert(mem.index == INVALID_REGISTER);
    assert(mem.disp == 0);

    size_t width = (assembly->getBytes()[3] & 0b10000000) ? 8 : 4;
    auto memTree0 = TreeFactory::instance().make<TreeNodeAddition>(
        baseTree,
        TreeFactory::instance().make<TreeNodeConstant>(0));
    auto memTree1 = TreeFactory::instance().make<TreeNodeAddition>(
        baseTree,
        TreeFactory::instance().make<TreeNodeConstant>(width));
    useMem(state, memTree0, reg0);
    useMem(state, memTree1, reg1);

    auto derefTree0
        = TreeFactory::instance().make<TreeNodeDereference>(memTree0, width);
    auto derefTree1
        = TreeFactory::instance().make<TreeNodeDereference>(memTree1, width);
    defReg(state, reg0, derefTree0);
    defReg(state, reg1, derefTree1);

    auto imm = assembly->getAsmOperands()->getOperands()[3].imm;
    auto wbTree = TreeFactory::instance().make<TreeNodeAddition>(
        baseTree,
        TreeFactory::instance().make<TreeNodeConstant>(imm));
    defReg(state, base, wbTree);
#endif
}

void UseDef::fillRegRegRegToReg(UDState *state, AssemblyPtr assembly) {
#ifdef ARCH_AARCH64
    auto op0 = assembly->getAsmOperands()->getOperands()[0].reg;
    int reg0 = AARCH64GPRegister::convertToPhysical(op0);
    auto op1 = assembly->getAsmOperands()->getOperands()[1].reg;
    int reg1 = AARCH64GPRegister::convertToPhysical(op1);
    size_t width1 = AARCH64GPRegister::getWidth(reg1, op1);
    auto op2 = assembly->getAsmOperands()->getOperands()[2].reg;
    int reg2 = AARCH64GPRegister::convertToPhysical(op2);
    size_t width2 = AARCH64GPRegister::getWidth(reg2, op2);
    auto op3 = assembly->getAsmOperands()->getOperands()[3].reg;
    int reg3 = AARCH64GPRegister::convertToPhysical(op3);
    size_t width3 = AARCH64GPRegister::getWidth(reg3, op3);

    useReg(state, reg1);
    useReg(state, reg2);
    useReg(state, reg3);

    TreeNode *reg1tree
        = TreeFactory::instance().make<TreeNodePhysicalRegister>(reg1, width1);
    TreeNode *reg2tree
        = TreeFactory::instance().make<TreeNodePhysicalRegister>(reg2, width2);
    TreeNode *reg3tree
        = TreeFactory::instance().make<TreeNodePhysicalRegister>(reg3, width3);

    TreeNode *tree = nullptr;
    switch(assembly->getId()) {
    case ARM64_INS_MADD: {
        auto subtree = TreeFactory::instance().make<
            TreeNodeMultiplication>(reg1tree, reg2tree);
        tree = TreeFactory::instance().make<
            TreeNodeAddition>(subtree, reg3tree);
        break;
    }
    default:
        tree = nullptr;
        LOG(10, "NYI: " << assembly->getMnemonic());
        break;
    }
    defReg(state, reg0, tree);
#endif
}

#ifdef ARCH_X86_64
size_t UseDef::inferAccessWidth(const cs_x86_op *op) {
    if(op->type != X86_OP_MEM && op->type != X86_OP_REG) {
        LOG(1, "don't know how to infer width of operand type "
            << static_cast<int>(op->type) << ", blindly assuming 8");
        return 8;  // default to 8
    }
    return op->size;
}
std::tuple<int, size_t> UseDef::getPhysicalRegister(int reg) {
    int id = X86Register::convertToPhysical(reg);
    size_t width = X86Register::getWidth(id, reg);
    return std::make_tuple(id, width);
}
// returns nullptr if all is zero (disp == 0); see fillMemToReg
TreeNode *UseDef::makeMemTree(UDState *state, const x86_op_mem& mem) {
    TreeNode *memTree = nullptr;
    if(mem.disp != 0) {
        // use TreeNodeConstant because it can be mem.disp < 0
        memTree = TreeFactory::instance().make<TreeNodeConstant>(mem.disp);
    }
    if(mem.index != INVALID_REGISTER) {
        int regI;
        size_t widthI;
        std::tie(regI, widthI) = getPhysicalRegister(mem.index);
        useReg(state, regI);
        TreeNode *indexTree = TreeFactory::instance().make<
            TreeNodePhysicalRegister>(regI, widthI);
        //if(mem.scale != 1) {
            indexTree = TreeFactory::instance().make<TreeNodeMultiplication>(
                indexTree,
                TreeFactory::instance().make<TreeNodeConstant>(mem.scale));
        //}
        if(memTree) {
            memTree = TreeFactory::instance().make<TreeNodeAddition>(
                indexTree, memTree);
        }
        else {
            memTree = indexTree;
        }
    }

    if(mem.base != INVALID_REGISTER) {
        TreeNode *baseTree = nullptr;
        if(mem.base == X86_REG_RIP) {
            auto instr = state->getInstruction();
            baseTree = TreeFactory::instance().make<TreeNodeRegisterRIP>(
                instr->getAddress() + instr->getSize());
        }
        else {
            int regB;
            size_t widthB;
            std::tie(regB, widthB) = getPhysicalRegister(mem.base);
            useReg(state, regB);
            baseTree = TreeFactory::instance().make<TreeNodePhysicalRegister>(
                regB, widthB);
        }
        if(memTree) {
            memTree = TreeFactory::instance().make<TreeNodeAddition>(
                baseTree, memTree);
        }
        else {
            memTree = baseTree;
        }
    }
    return memTree;
}
void UseDef::fillAddOrSub(UDState *state, AssemblyPtr assembly) {
    auto mode = assembly->getAsmOperands()->getMode();
    if(mode == AssemblyOperands::MODE_IMM_REG) {
        fillImmToReg(state, assembly);
    }
    else if(mode == AssemblyOperands::MODE_REG_REG) {
        fillRegToReg(state, assembly);
    }
    else if(mode == AssemblyOperands::MODE_MEM_REG) {
        size_t width = inferAccessWidth(
            &assembly->getAsmOperands()->getOperands()[0]);
        fillMemToReg(state, assembly, width);
    }
    else {
        LOG(10, "skipping mode " << mode);
    }
}
void UseDef::fillAnd(UDState *state, AssemblyPtr assembly) {
    auto mode = assembly->getAsmOperands()->getMode();
    if(mode == AssemblyOperands::MODE_IMM_REG) {
        fillImmToReg(state, assembly);
    }
    else {
        LOG(10, "skipping mode " << mode);
    }
}
void UseDef::fillBsf(UDState *state, AssemblyPtr assembly) {
    auto mode = assembly->getAsmOperands()->getMode();
    if(mode == AssemblyOperands::MODE_REG_REG) {
        int reg0, reg1;
        std::tie(reg0, std::ignore) = getPhysicalRegister(
            assembly->getAsmOperands()->getOperands()[0].reg);
        std::tie(reg1, std::ignore) = getPhysicalRegister(
            assembly->getAsmOperands()->getOperands()[1].reg);
        defReg(state, reg0, nullptr);
        useReg(state, reg1);
    }
    else {
        LOG(10, "skipping mode " << mode);
    }
}
void UseDef::fillBt(UDState *state, AssemblyPtr assembly) {
    auto mode = assembly->getAsmOperands()->getMode();
    if(mode == AssemblyOperands::MODE_REG_REG) {
        int reg0, reg1;
        size_t width0, width1;
        std::tie(reg0, width0) = getPhysicalRegister(
            assembly->getAsmOperands()->getOperands()[0].reg);
        useReg(state, reg0);
        std::tie(reg1, width1) = getPhysicalRegister(
            assembly->getAsmOperands()->getOperands()[1].reg);
        useReg(state, reg1);
        auto tree0 = TreeFactory::instance().make<TreeNodePhysicalRegister>(
            reg0, width0);
        auto tree1 = TreeFactory::instance().make<TreeNodePhysicalRegister>(
            reg1, width1);
        auto tree = TreeFactory::instance().make<TreeNodeAnd>(tree0, tree1);
        defReg(state, X86Register::FLAGS, tree);
    }
    else if(mode == AssemblyOperands::MODE_MEM_REG) {
        int reg0;
        std::tie(reg0, std::ignore) = getPhysicalRegister(
            assembly->getAsmOperands()->getOperands()[0].reg);
        useReg(state, reg0);
        defReg(state, X86Register::FLAGS, nullptr);
        LOG(10, "NYI (fully): " << assembly->getMnemonic());
    }
    else {
        defReg(state, X86Register::FLAGS, nullptr);
        LOG(10, "skipping mode " << mode);
    }
}
void UseDef::fillCall(UDState *state, AssemblyPtr assembly) {
    for(int i = 0; i < 3; i++) {
        useReg(state, i);
        defReg(state, i, nullptr);
    }
    for(int i = 6; i < 12; i++) {
        useReg(state, i);
        defReg(state, i, nullptr);
    }
}
void UseDef::fillCmp(UDState *state, AssemblyPtr assembly) {
    auto mode = assembly->getAsmOperands()->getMode();
    if(mode == AssemblyOperands::MODE_REG_REG) {
        int reg0, reg1;
        size_t width0, width1;
        std::tie(reg0, width0) = getPhysicalRegister(
            assembly->getAsmOperands()->getOperands()[0].reg);
        useReg(state, reg0);
        std::tie(reg1, width1) = getPhysicalRegister(
            assembly->getAsmOperands()->getOperands()[1].reg);
        useReg(state, reg1);

        auto tree0 = TreeFactory::instance().make<TreeNodePhysicalRegister>(
            reg0, width0);
        auto tree1 = TreeFactory::instance().make<TreeNodePhysicalRegister>(
            reg1, width1);
        auto tree = TreeFactory::instance().make<TreeNodeComparison>(
            tree1, tree0);
        defReg(state, X86Register::FLAGS, tree);
    }
    else if(mode == AssemblyOperands::MODE_IMM_REG) {
        auto imm = assembly->getAsmOperands()->getOperands()[0].imm;
        int reg1, width1;
        std::tie(reg1, width1) = getPhysicalRegister(
            assembly->getAsmOperands()->getOperands()[1].reg);
        useReg(state, reg1);
        auto tree0 = TreeFactory::instance().make<TreeNodeConstant>(imm);
        auto tree1 = TreeFactory::instance().make<TreeNodePhysicalRegister>(
            reg1, width1);
        auto tree = TreeFactory::instance().make<TreeNodeComparison>(
            tree1, tree0);
        defReg(state, X86Register::FLAGS, tree);
    }
    else if(mode == AssemblyOperands::MODE_IMM_MEM) {
        auto imm = assembly->getAsmOperands()->getOperands()[0].imm;
        auto tree0 = TreeFactory::instance().make<TreeNodeConstant>(imm);
        auto memTree = makeMemTree(
            state, assembly->getAsmOperands()->getOperands()[1].mem);
        auto tree1 = TreeFactory::instance().make<TreeNodeDereference>(
            memTree, 8);    // !!!
        auto tree = TreeFactory::instance().make<TreeNodeComparison>(
            tree1, tree0);
        defReg(state, X86Register::FLAGS, tree);
    }
    else {
        defReg(state, X86Register::FLAGS, nullptr);
        LOG(10, "skipping mode " << mode);
    }
}
void UseDef::fillInc(UDState *state, AssemblyPtr assembly) {
    auto mode = assembly->getAsmOperands()->getMode();
    if(mode == AssemblyOperands::MODE_REG) {
        int reg0;
        size_t width0;
        std::tie(reg0, width0) = getPhysicalRegister(
            assembly->getAsmOperands()->getOperands()[0].reg);
        if(reg0 < 0) return;
        useReg(state, reg0);
        auto reg0Tree = TreeFactory::instance().make<TreeNodePhysicalRegister>(
            reg0, width0);
        auto oneTree = TreeFactory::instance().make<TreeNodeConstant>(1);
        auto tree = TreeFactory::instance().make<TreeNodeAddition>(
            reg0Tree, oneTree);
        defReg(state, reg0, tree);
    }
    else {
        LOG(10, "skipping mode " << mode);
    }
}
void UseDef::fillJa(UDState *state, AssemblyPtr assembly) {
    useReg(state, X86Register::FLAGS);
    //LOG(1, "does this instruction use/def any other registers?");
}
void UseDef::fillJae(UDState *state, AssemblyPtr assembly) {
    useReg(state, X86Register::FLAGS);
    //LOG(1, "does this instruction use/def any other registers?");
}
void UseDef::fillJb(UDState *state, AssemblyPtr assembly) {
    useReg(state, X86Register::FLAGS);
    //LOG(1, "does this instruction use/def any other registers?");
}
void UseDef::fillJbe(UDState *state, AssemblyPtr assembly) {
    useReg(state, X86Register::FLAGS);
    //LOG(1, "does this instruction use/def any other registers?");
}
void UseDef::fillJe(UDState *state, AssemblyPtr assembly) {
    useReg(state, X86Register::FLAGS);
    //LOG(1, "does this instruction use/def any other registers?");
}
void UseDef::fillJne(UDState *state, AssemblyPtr assembly) {
    useReg(state, X86Register::FLAGS);
    //LOG(1, "does this instruction use/def any other registers?");
}
void UseDef::fillJg(UDState *state, AssemblyPtr assembly) {
    useReg(state, X86Register::FLAGS);
    //LOG(1, "does this instruction use/def any other registers?");
}
void UseDef::fillJge(UDState *state, AssemblyPtr assembly) {
    useReg(state, X86Register::FLAGS);
    //LOG(1, "does this instruction use/def any other registers?");
}
void UseDef::fillJl(UDState *state, AssemblyPtr assembly) {
    useReg(state, X86Register::FLAGS);
    //LOG(1, "does this instruction use/def any other registers?");
}
void UseDef::fillJle(UDState *state, AssemblyPtr assembly) {
    useReg(state, X86Register::FLAGS);
    //LOG(1, "does this instruction use/def any other registers?");
}
void UseDef::fillJmp(UDState *state, AssemblyPtr assembly) {
    auto semantic = state->getInstruction()->getSemantic();
    if(auto ij = dynamic_cast<IndirectJumpInstruction *>(semantic)) {
        if(ij->getRegister() != X86_REG_RIP) {
            int reg;
            std::tie(reg, std::ignore) = getPhysicalRegister(ij->getRegister());
            useReg(state, reg);
        }
    }
    else if(auto cfi = dynamic_cast<ControlFlowInstruction *>(semantic)) {
        // external jumps should preserve ABI registers.
        if(cfi->getLink()->isExternalJump()) {
            for(int i = 0; i < 3; i++) {
                useReg(state, i);
            }
            for(int i = 6; i < 12; i++) {
                useReg(state, i);
            }
        }
    }
#if 0
    // %gs: direct jump becomes IsolatedInstruction
    else if(!dynamic_cast<ControlFlowInstruction *>(semantic)) {
        throw "what is this?";
    }
#endif
    //LOG(1, "does this instruction use/def any other registers?");
}
void UseDef::fillLea(UDState *state, AssemblyPtr assembly) {
    auto mode = assembly->getAsmOperands()->getMode();
    if(mode == AssemblyOperands::MODE_MEM_REG) {
        size_t width = inferAccessWidth(
            &assembly->getAsmOperands()->getOperands()[0]);
        fillMemToReg(state, assembly, width);
    }
    else {
        LOG(10, "skipping mode " << mode);
    }
}
void UseDef::fillMov(UDState *state, AssemblyPtr assembly) {
    auto mode = assembly->getAsmOperands()->getMode();
    if(mode == AssemblyOperands::MODE_REG_MEM) {
        size_t width = inferAccessWidth(
            &assembly->getAsmOperands()->getOperands()[0]);
        fillRegToMem(state, assembly, width);
    }
    else if(mode == AssemblyOperands::MODE_MEM_REG) {
        size_t width = inferAccessWidth(
            &assembly->getAsmOperands()->getOperands()[1]);
        fillMemToReg(state, assembly, width);
    }
    else if(mode == AssemblyOperands::MODE_REG_REG) {
        fillRegToReg(state, assembly);
    }
    else if(mode == AssemblyOperands::MODE_IMM_REG) {
        fillImmToReg(state, assembly);
    }
    else {
        LOG(10, "skipping mode " << mode);
    }
}
void UseDef::fillMovabs(UDState *state, AssemblyPtr assembly) {
    auto mode = assembly->getAsmOperands()->getMode();
    assert(mode == AssemblyOperands::MODE_IMM_REG);
    if(mode == AssemblyOperands::MODE_IMM_REG) {
        fillImmToReg(state, assembly);
    }
    else {
        LOG(10, "skipping mode " << mode);
    }
}
void UseDef::fillMovsxd(UDState *state, AssemblyPtr assembly) {
    fillMov(state, assembly);
}
void UseDef::fillMovzx(UDState *state, AssemblyPtr assembly) {
    fillMov(state, assembly);
}
void UseDef::fillSyscall(UDState *state, AssemblyPtr assembly) {
    // On Linux, syscall uses rax as the syscall number, and then rdi, rsi,
    // rdx, r10, r8, r9 as the arguments.
    useReg(state, X86Register::convertToPhysical(X86_REG_RAX));
    useReg(state, X86Register::convertToPhysical(X86_REG_RDI));
    useReg(state, X86Register::convertToPhysical(X86_REG_RSI));
    useReg(state, X86Register::convertToPhysical(X86_REG_RDX));
    useReg(state, X86Register::convertToPhysical(X86_REG_R10));
    useReg(state, X86Register::convertToPhysical(X86_REG_R8));
    useReg(state, X86Register::convertToPhysical(X86_REG_R9));

    // On Linux, the syscall calling convention allows rax, rcx, and r11 to be
    // clobbered to unknown values, but no others.
    defReg(state, X86Register::convertToPhysical(X86_REG_RAX), nullptr);
    defReg(state, X86Register::convertToPhysical(X86_REG_RCX), nullptr);
    defReg(state, X86Register::convertToPhysical(X86_REG_R11), nullptr);
}
void UseDef::fillTest(UDState *state, AssemblyPtr assembly) {
    defReg(state, X86Register::FLAGS, nullptr);
    LOG(10, "NYI (fully): " << assembly->getMnemonic());
}
void UseDef::fillPush(UDState *state, AssemblyPtr assembly) {
    auto mode = assembly->getAsmOperands()->getMode();
    if(mode == AssemblyOperands::MODE_REG) {
        size_t width = inferAccessWidth(
            &assembly->getAsmOperands()->getOperands()[0]);
        fillRegToMem(state, assembly, width);
    }
    else {
        LOG(10, "skipping mode " << mode);
    }
}
void UseDef::fillXor(UDState *state, AssemblyPtr assembly) {
    auto mode = assembly->getAsmOperands()->getMode();
    if(mode == AssemblyOperands::MODE_REG_REG) {
        auto op0 = assembly->getAsmOperands()->getOperands()[0].reg;
        auto op1 = assembly->getAsmOperands()->getOperands()[1].reg;
        if(op0 == op1) {
            int reg0;
            std::tie(reg0, std::ignore) = getPhysicalRegister(op0);

            defReg(state, reg0,
                TreeFactory::instance().make<TreeNodeConstant>(0));
        }
    }
    LOG(10, "NYI (fully): " << assembly->getMnemonic());
}
#endif

#ifdef ARCH_AARCH64
void UseDef::fillAddOrSub(UDState *state, AssemblyPtr assembly) {
    auto mode = assembly->getAsmOperands()->getMode();
    if(mode == AssemblyOperands::MODE_REG_REG_IMM) {
        fillRegImmToReg(state, assembly);
    }
    else if(mode == AssemblyOperands::MODE_REG_REG_REG) {
        fillRegRegToReg(state, assembly);
    }
    else {
        LOG(10, "skipping mode " << mode);
    }
}
void UseDef::fillAdr(UDState *state, AssemblyPtr assembly) {
    fillImmToReg(state, assembly);
}
void UseDef::fillAdrp(UDState *state, AssemblyPtr assembly) {
    fillImmToReg(state, assembly);
}
void UseDef::fillAnd(UDState *state, AssemblyPtr assembly) {
    auto mode = assembly->getAsmOperands()->getMode();
    if(mode == AssemblyOperands::MODE_REG_REG_IMM) {
        fillRegImmToReg(state, assembly);
    }
    else if(mode == AssemblyOperands::MODE_REG_REG_REG) {
        fillRegRegToReg(state, assembly);
    }
    else {
        LOG(10, "skipping mode " << mode);
    }
}
void UseDef::fillB(UDState *state, AssemblyPtr assembly) {
    if(assembly->getMnemonic() != "b") {
        useReg(state, AARCH64GPRegister::NZCV);
    }
}
void UseDef::fillBl(UDState *state, AssemblyPtr assembly) {
    for(int i = 0; i < 19; i++) {
        useReg(state, i);
        defReg(state, i, nullptr);
    }
    defReg(state, 30, nullptr);
    auto link = state->getInstruction()->getSemantic()->getLink();
    if(dynamic_cast<PLTLink *>(link)) {
        defReg(state, 16, nullptr);
        defReg(state, 17, nullptr);
    }
}
void UseDef::fillBlr(UDState *state, AssemblyPtr assembly) {
    fillReg(state, assembly);

    for(int i = 0; i < 9; i++) {
        useReg(state, i);
        defReg(state, i, nullptr);
    }
    for(int i = 9; i < 19; i++) {
        defReg(state, i, nullptr);
    }
    defReg(state, 30, nullptr);
}
void UseDef::fillBr(UDState *state, AssemblyPtr assembly) {
    fillReg(state, assembly);

    auto instr = state->getInstruction();
    auto ij = dynamic_cast<IndirectJumpInstruction *>(instr->getSemantic());
    if(ij && ij->isForJumpTable()) {
        for(int i = 0; i < 9; i++) {
            useReg(state, i);
            defReg(state, i, nullptr);
        }
        for(int i = 9; i < 19; i++) {
            defReg(state, i, nullptr);
        }
    }
}
void UseDef::fillCbz(UDState *state, AssemblyPtr assembly) {
    auto op0 = assembly->getAsmOperands()->getOperands()[0].reg;
    int reg0 = AARCH64GPRegister::convertToPhysical(op0);
    size_t width0 = AARCH64GPRegister::getWidth(reg0, op0);
    useReg(state, reg0);

    auto tree = TreeFactory::instance().make<TreeNodeComparison>(
        TreeFactory::instance().make<TreeNodePhysicalRegister>(reg0, width0),
        TreeFactory::instance().make<TreeNodeConstant>(0));
    defReg(state, AARCH64GPRegister::ONETIME_NZCV, tree);
}
void UseDef::fillCbnz(UDState *state, AssemblyPtr assembly) {
    auto op0 = assembly->getAsmOperands()->getOperands()[0].reg;
    int reg0 = AARCH64GPRegister::convertToPhysical(op0);
    size_t width0 = AARCH64GPRegister::getWidth(reg0, op0);
    useReg(state, reg0);

    auto tree = TreeFactory::instance().make<TreeNodeComparison>(
        TreeFactory::instance().make<TreeNodePhysicalRegister>(reg0, width0),
        TreeFactory::instance().make<TreeNodeConstant>(0));
    defReg(state, AARCH64GPRegister::ONETIME_NZCV, tree);
}
void UseDef::fillCmp(UDState *state, AssemblyPtr assembly) {
    auto op0 = assembly->getAsmOperands()->getOperands()[0].reg;
    int reg0 = AARCH64GPRegister::convertToPhysical(op0);
    size_t width0 = AARCH64GPRegister::getWidth(reg0, op0);
    useReg(state, reg0);

    auto imm = assembly->getAsmOperands()->getOperands()[1].imm;
    auto tree = TreeFactory::instance().make<TreeNodeComparison>(
        TreeFactory::instance().make<TreeNodePhysicalRegister>(reg0, width0),
        TreeFactory::instance().make<TreeNodeConstant>(imm));
    defReg(state, AARCH64GPRegister::NZCV, tree);
}
void UseDef::fillCsel(UDState *state, AssemblyPtr assembly) {
    auto op0 = assembly->getAsmOperands()->getOperands()[0].reg;
    int reg0 = AARCH64GPRegister::convertToPhysical(op0);
    size_t width0 = AARCH64GPRegister::getWidth(reg0, op0);
    defReg(state,
        reg0,
        TreeFactory::instance().make<TreeNodePhysicalRegister>(reg0, width0));
    LOG(10, "NYI: " << assembly->getMnemonic());
}
void UseDef::fillCset(UDState *state, AssemblyPtr assembly) {
    auto op0 = assembly->getAsmOperands()->getOperands()[0].reg;
    int reg0 = AARCH64GPRegister::convertToPhysical(op0);
    size_t width0 = AARCH64GPRegister::getWidth(reg0, op0);
    defReg(state,
        reg0,
        TreeFactory::instance().make<TreeNodePhysicalRegister>(reg0, width0));
    LOG(10, "NYI: " << assembly->getMnemonic());
}
void UseDef::fillEor(UDState *state, AssemblyPtr assembly) {
    auto op0 = assembly->getAsmOperands()->getOperands()[0].reg;
    int reg0 = AARCH64GPRegister::convertToPhysical(op0);
    size_t width0 = AARCH64GPRegister::getWidth(reg0, op0);
    defReg(state,
        reg0,
        TreeFactory::instance().make<TreeNodePhysicalRegister>(reg0, width0));
    LOG(10, "NYI (fully): " << assembly->getMnemonic());
}
void UseDef::fillFmov(UDState *state, AssemblyPtr assembly) {
    auto op0 = assembly->getAsmOperands()->getOperands()[0].reg;
    int reg0 = AARCH64GPRegister::convertToPhysical(op0);
    defReg(state, reg0, nullptr);
    LOG(10, "NYI (fully): " << assembly->getMnemonic());
}
void UseDef::fillLdaxr(UDState *state, AssemblyPtr assembly) {
    auto mode = assembly->getAsmOperands()->getMode();
    if(mode == AssemblyOperands::MODE_REG_MEM) {
        size_t width = (assembly->getBytes()[3] & 0b01000000) ? 8 : 4;
        fillMemToReg(state, assembly, width);
    }
    else {
        throw "unknown mode for LDAXR";
    }
}
void UseDef::fillLdp(UDState *state, AssemblyPtr assembly) {
    auto mode = assembly->getAsmOperands()->getMode();
    if(mode == AssemblyOperands::MODE_REG_REG_MEM) {
        fillMemToRegReg(state, assembly);
    }
    else if(mode == AssemblyOperands::MODE_REG_REG_MEM_IMM) {
        fillMemImmToRegReg(state, assembly);
    }
    else {
        throw "unknown mode for LDP";
    }
}
void UseDef::fillLdr(UDState *state, AssemblyPtr assembly) {
    auto mode = assembly->getAsmOperands()->getMode();
    if(mode == AssemblyOperands::MODE_REG_MEM) {
        size_t width = (assembly->getBytes()[3] & 0b01000000) ? 8 : 4;
        fillMemToReg(state, assembly, width);
    }
    else if(mode == AssemblyOperands::MODE_REG_MEM_IMM) {
        fillMemImmToReg(state, assembly);
    }
    else if(mode == AssemblyOperands::MODE_REG_IMM) {
        fillImmToReg(state, assembly);
    }
    else {
        LOG(10, "skipping mode " << mode);
    }
}
void UseDef::fillLdrh(UDState *state, AssemblyPtr assembly) {
    auto mode = assembly->getAsmOperands()->getMode();
    if(mode == AssemblyOperands::MODE_REG_MEM) {
        fillMemToReg(state, assembly, 2);
    }
    else {
        LOG(10, "skipping mode " << mode);
    }
}
void UseDef::fillLdrb(UDState *state, AssemblyPtr assembly) {
    auto mode = assembly->getAsmOperands()->getMode();
    if(mode == AssemblyOperands::MODE_REG_MEM) {
        fillMemToReg(state, assembly, 1);
    }
    else {
        LOG(10, "skipping mode " << mode);
    }
}
void UseDef::fillLdrsw(UDState *state, AssemblyPtr assembly) {
    auto mode = assembly->getAsmOperands()->getMode();
    if(mode == AssemblyOperands::MODE_REG_MEM) {
        fillMemToReg(state, assembly, 4);
    }
    else {
        LOG(10, "skipping mode " << mode);
    }
}
void UseDef::fillLdrsh(UDState *state, AssemblyPtr assembly) {
    auto mode = assembly->getAsmOperands()->getMode();
    if(mode == AssemblyOperands::MODE_REG_MEM) {
        fillMemToReg(state, assembly, 2);
    }
    else {
        LOG(10, "skipping mode " << mode);
    }
}
void UseDef::fillLdrsb(UDState *state, AssemblyPtr assembly) {
    auto mode = assembly->getAsmOperands()->getMode();
    if(mode == AssemblyOperands::MODE_REG_MEM) {
        fillMemToReg(state, assembly, 1);
    }
    else {
        LOG(10, "skipping mode " << mode);
    }
}
void UseDef::fillLdur(UDState *state, AssemblyPtr assembly) {
    auto mode = assembly->getAsmOperands()->getMode();
    if(mode == AssemblyOperands::MODE_REG_MEM) {
        size_t width = (assembly->getBytes()[3] & 0b01000000) ? 8 : 4;
        fillMemToReg(state, assembly, width);
    }
    else {
        LOG(10, "skipping mode " << mode);
    }
}
void UseDef::fillLsl(UDState *state, AssemblyPtr assembly) {
    auto mode = assembly->getAsmOperands()->getMode();
    if(mode == AssemblyOperands::MODE_REG_REG_IMM) {
        fillRegImmToReg(state, assembly);
    }
    else if(mode == AssemblyOperands::MODE_REG_REG_REG) {
        fillRegRegToReg(state, assembly);
    }
    else {
        LOG(10, "skipping mode " << mode);
    }
}
void UseDef::fillMadd(UDState *state, AssemblyPtr assembly) {
    auto mode = assembly->getAsmOperands()->getMode();
    if(mode == AssemblyOperands::MODE_REG_REG_REG_REG) {
        fillRegRegRegToReg(state, assembly);
    }
    else {
        throw "unknown mode for Madd";
    }
}
void UseDef::fillNop(UDState *state, AssemblyPtr assembly) {
    /* Nothing to do */
}
void UseDef::fillOrr(UDState *state, AssemblyPtr assembly) {
    auto op0 = assembly->getAsmOperands()->getOperands()[0].reg;
    int reg0 = AARCH64GPRegister::convertToPhysical(op0);
    size_t width0 = AARCH64GPRegister::getWidth(reg0, op0);
    defReg(state,
        reg0,
        TreeFactory::instance().make<TreeNodePhysicalRegister>(reg0, width0));
    LOG(10, "NYI (fully): " << assembly->getMnemonic());
}
void UseDef::fillMov(UDState *state, AssemblyPtr assembly) {
    auto mode = assembly->getAsmOperands()->getMode();
    if(mode == AssemblyOperands::MODE_REG_REG) {
        fillRegToReg(state, assembly);
    }
    else if(mode == AssemblyOperands::MODE_REG_IMM) {
        fillImmToReg(state, assembly);
    }
    else {
        LOG(10, "skipping mode " << mode);
    }
}
void UseDef::fillMrs(UDState *state, AssemblyPtr assembly) {
    auto op0 = assembly->getAsmOperands()->getOperands()[0].reg;
    int reg0 = AARCH64GPRegister::convertToPhysical(op0);
    size_t width0 = AARCH64GPRegister::getWidth(reg0, op0);
    defReg(state,
        reg0,
        TreeFactory::instance().make<TreeNodePhysicalRegister>(reg0, width0));
}
void UseDef::fillRet(UDState *state, AssemblyPtr assembly) {
    for(int i = 0; i < 8; i++) {
        useReg(state, i);
    }
}
void UseDef::fillStp(UDState *state, AssemblyPtr assembly) {
    auto mode = assembly->getAsmOperands()->getMode();
    if(mode == AssemblyOperands::MODE_REG_REG_MEM) {
        fillRegRegToMem(state, assembly);
    }
    else if(mode == AssemblyOperands::MODE_REG_REG_MEM_IMM) {
        fillRegRegImmToMem(state, assembly);
    }
    else {
        throw "unknown mode for STP";
    }
}
void UseDef::fillStr(UDState *state, AssemblyPtr assembly) {
    auto mode = assembly->getAsmOperands()->getMode();
    if(mode == AssemblyOperands::MODE_REG_MEM) {
        size_t width = (assembly->getBytes()[3] & 0b01000000) ? 8 : 4;
        fillRegToMem(state, assembly, width);
    }
    else {
        LOG(10, "skipping mode " << mode);
    }
}
void UseDef::fillStrb(UDState *state, AssemblyPtr assembly) {
    auto mode = assembly->getAsmOperands()->getMode();
    if(mode == AssemblyOperands::MODE_REG_MEM) {
        fillRegToMem(state, assembly, 1);
    }
    else {
        LOG(10, "skipping mode " << mode);
    }
}
void UseDef::fillStrh(UDState *state, AssemblyPtr assembly) {
    auto mode = assembly->getAsmOperands()->getMode();
    if(mode == AssemblyOperands::MODE_REG_MEM) {
        fillRegToMem(state, assembly, 2);
    }
    else {
        LOG(10, "skipping mode " << mode);
    }
}
void UseDef::fillSxtw(UDState *state, AssemblyPtr assembly) {
    auto mode = assembly->getAsmOperands()->getMode();
    if(mode == AssemblyOperands::MODE_REG_REG) {
        LOG(10, "NYI fully: " << assembly->getMnemonic());
        fillRegToReg(state, assembly);
    }
    else {
        LOG(10, "skipping mode " << mode);
    }
}
void UseDef::fillUbfiz(UDState *state, AssemblyPtr assembly) {
    auto mode = assembly->getAsmOperands()->getMode();
    if(mode == AssemblyOperands::MODE_REG_REG_IMM_IMM) {
        LOG(10, "NYI fully: " << assembly->getMnemonic());

        auto op0 = assembly->getAsmOperands()->getOperands()[0].reg;
        int reg0 = AARCH64GPRegister::convertToPhysical(op0);
        defReg(state, reg0, nullptr);
    }
    else {
        LOG(10, "skipping mode " << mode);
    }
}
#endif

#ifdef ARCH_RISCV
void UseDef::fillB(UDState *state, AssemblyPtr assembly) {
    // mark relevant registers as used
    size_t count = assembly->getAsmOperands()->getOpCount();
    const rv_oper *opers = assembly->getAsmOperands()->getOperands();

    for(size_t i = 0; i < count; i ++) {
        if(opers[i].type == rv_oper::rv_oper_reg)
            useReg(state, opers[i].value.reg);
    }
}

void UseDef::fillJ(UDState *state, AssemblyPtr assembly) {
    // nothing to do
}

void UseDef::fillJal(UDState *state, AssemblyPtr assembly) {
    useReg(state, assembly->getAsmOperands()->getOperands()[0].value.reg);
}

void UseDef::fillJalr(UDState *state, AssemblyPtr assembly) {

}

void UseDef::fillJr(UDState *state, AssemblyPtr assembly) {
    useReg(state, assembly->getAsmOperands()->getOperands()[0].value.reg);
}

void UseDef::fillLoad(UDState *state, AssemblyPtr assembly) {
    fillMemToReg(state, assembly, -1);
}

void UseDef::fillRet(UDState *state, AssemblyPtr assembly) {
    // return registers are {f,}a0/a1
    useReg(state, rv_ireg_a0);
    useReg(state, rv_ireg_a1);
    useReg(state, rv_freg_fa0);
    useReg(state, rv_freg_fa1);
}

void UseDef::fillStore(UDState *state, AssemblyPtr assembly) {
    fillRegToMem(state, assembly, -1);
}

#endif

void MemLocation::extract(TreeNode *tree) {
    typedef TreePatternRecursiveBinary<TreeNodeAddition,
        TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>,
        TreePatternCapture<TreePatternTerminal<TreeNodeConstant>>
    > MemoryForm;

    TreeCapture cap;
    if(MemoryForm::matches(tree, cap)) {
        for(size_t i = 0; i < cap.getCount(); ++i) {
            auto c = cap.get(i);
            if(auto t = dynamic_cast<TreeNodeConstant *>(c)) {
                offset += t->getValue();
            }
            else if(auto t = dynamic_cast<TreeNodePhysicalRegister *>(c)) {
                reg = t;
            }
        }
    }
    else {
        reg = tree;
        offset = 0;
    }
}

#ifdef ARCH_AARCH64
bool StateGroup::isPushOrPop(const UDState *state) {
    typedef TreePatternRecursiveBinary<TreeNodeAddition,
        TreePatternPhysicalRegisterIs<AARCH64GPRegister::SP>,
        TreePatternTerminal<TreeNodeConstant>
    > PushForm;

    typedef TreePatternUnary<TreeNodeDereference,
        PushForm
    > PopForm;

    TreeCapture cap;
    for(auto mem : state->getMemDefList()) {
        if(PushForm::matches(mem.second, cap)) {
            return true;
        }
    }
    for(auto reg : state->getRegDefList()) {
        if(PopForm::matches(reg.second, cap)) {
            return true;
        }
    }
    return false;
}

bool StateGroup::isDirectCall(const UDState *state) {
    auto instr = state->getInstruction();
    auto semantic = instr->getSemantic();
    if(auto assembly = semantic->getAssembly()) {
        if(assembly->getId() == ARM64_INS_BL) return true;
    }

    return false;
}

bool StateGroup::isIndirectCall(const UDState *state) {
    auto instr = state->getInstruction();
    auto semantic = instr->getSemantic();
    if(auto assembly = semantic->getAssembly()) {
        if(assembly->getId() == ARM64_INS_BLR) return true;
    }

    return false;
}

bool StateGroup::isCall(const UDState *state) {
    auto instr = state->getInstruction();
    auto semantic = instr->getSemantic();
    if(auto assembly = semantic->getAssembly()) {
        if(assembly->getId() == ARM64_INS_BL) return true;
        if(assembly->getId() == ARM64_INS_BLR) return true;
    }

    return false;
}

bool StateGroup::isExternalJump(const UDState *state, Module *module) {
    auto instr = state->getInstruction();
    auto semantic = instr->getSemantic();
    if(dynamic_cast<ControlFlowInstruction *>(semantic)) {
        if(StateGroup::isCall(state)) return false;

        // B or B.cond
        auto link = semantic->getLink();
        if(dynamic_cast<Function *>(&*link->getTarget())) return true;
        if(dynamic_cast<PLTLink *>(link)) return true;
    }
    else if(dynamic_cast<IndirectJumpInstruction *>(semantic)) {
        // BR
        return !StateGroup::isJumpTableJump(state, module);
    }

    return false;
}
#endif

bool StateGroup::isJumpTableJump(const UDState *state, Module *module) {
    auto instr = state->getInstruction();
    auto semantic = instr->getSemantic();
    if(auto ij = dynamic_cast<IndirectJumpInstruction *>(semantic)) {
        if(ij->isForJumpTable()) {
            return true;
        }
    }

    return false;
}

bool StateGroup::isReturn(const UDState *state) {
    auto instr = state->getInstruction();
    auto semantic = instr->getSemantic();
    if(dynamic_cast<ReturnInstruction *>(semantic)) {
        return true;
    }
    return false;
}
