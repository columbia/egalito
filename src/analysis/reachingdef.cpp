#include <cassert>
#include <algorithm>
#include "reachingdef.h"
#include "chunk/concrete.h"
#include "chunk/dump.h"
#include "instr/concrete.h"
#include "instr/register.h"
#include "log/log.h"

void ReachingDef::analyze() {
#ifdef ARCH_X86_64
    #define INVALID_ID  X86_INS_INVALID
#elif defined(ARCH_AARCH64)
    #define INVALID_ID  ARM64_INS_INVALID
#endif
    for(auto instr : CIter::children(block)) {
        AssemblyPtr assembly = instr->getSemantic()->getAssembly();
        int id = INVALID_ID;
        if(assembly) {
            id = assembly->getId();
        }
        else {
#ifdef ARCH_X86_64
            auto v = dynamic_cast<ControlFlowInstruction *>(
                instr->getSemantic());
            if(v) id = v->getId();
#else
            LOG(1, __func__ << ": how do we gent id?");
#endif
        }

        auto it = handlers.find(id);
        if(it != handlers.end()) {
            auto f = it->second;
            (this->*f)(instr, assembly);
        }
        else {
            setBarrier(instr);
        }
    }
}

void ReachingDef::visitInstructionGroups(VisitCallback callback) {
    std::set<Instruction *> available;
    for(auto instr : CIter::children(block)) {
        available.insert(instr);
    }

    std::set<Instruction *> visited;
    for(;;) {
        std::vector<Instruction *> group;
        for(auto a : available) {
            if(areDependenciesCovered(a, visited)) {
                group.push_back(a);
            }
        }

        if(group.empty()) {
            if(!available.empty()) {
                LOG(1, "WARNING: aborting ReachingDef::visitInstructionGroups"
                    " with some instructions still remaining!");
            }
            break;
        }

        auto chosen = callback(group);
        available.erase(available.find(chosen));
        visited.insert(chosen);
    }
}

bool ReachingDef::areDependenciesCovered(Instruction *instr,
    const std::set<Instruction *> &covered) {

    for(const auto &dependency : killMap[instr]) {
        if(covered.find(dependency) == covered.end()) return false;
        if(!areDependenciesCovered(dependency, covered)) return false;
    }

    return true;
}

void ReachingDef::setBarrier(Instruction *instr) {
    for(Chunk *c = instr->getPreviousSibling(); c; c = c->getPreviousSibling()) {
        if(auto v = dynamic_cast<Instruction *>(c)) {
            killMap[instr].insert(v);
        }
    }

    for(int r = 0; r <= X86Register::REGISTER_NUMBER; r ++) {
        currentAccessMap[r] = { instr };
    }
}

void ReachingDef::dump() {
    for(auto instr : CIter::children(block)) {
        LOG0(1, "affects of " << instr->getName() << ", ");
        ChunkDumper dump;
        instr->accept(&dump);
        auto it = killMap.find(instr);
        if(it == killMap.end()) continue;

        const auto &set = (*it).second;
        for(auto kill : set) {
            LOG0(1, "    kills " << kill->getName() << ", ");
            ChunkDumper dump;
            kill->accept(&dump);
        }
    }
}

const std::map<int, ReachingDef::HandlerType> ReachingDef::handlers = {
#ifdef ARCH_X86_64
    {X86_INS_AND,       &ReachingDef::fillAnd},
    {X86_INS_ADD,       &ReachingDef::fillAddOrSub},
    {X86_INS_CMP,       &ReachingDef::fillCmp},
    {X86_INS_LEA,       &ReachingDef::fillLea},
    {X86_INS_MOV,       &ReachingDef::fillMov},
    {X86_INS_MOVABS,    &ReachingDef::fillMovabs},
    {X86_INS_MOVSXD,    &ReachingDef::fillMovsxd},
    {X86_INS_MOVZX,     &ReachingDef::fillMovzx},
    {X86_INS_PUSH,      &ReachingDef::fillPush},
    {X86_INS_POP,       &ReachingDef::fillPop},
    {X86_INS_SUB,       &ReachingDef::fillAddOrSub},
#endif
};

void ReachingDef::setRegRead(int reg, Instruction *instr) {
    currentAccessMap[reg].insert(instr);
}

void ReachingDef::setRegWrite(int reg, Instruction *instr) {
    killMap[instr] = currentAccessMap[reg];
    currentAccessMap[reg] = { instr };
}

int ReachingDef::getReg(AssemblyPtr assembly, int index) {
    auto op = assembly->getAsmOperands()->getOperands()[index].reg;

    return X86Register::convertToPhysical(op);
}

void ReachingDef::handleMem(AssemblyPtr assembly, int index, Instruction *instr) {
    auto mem = assembly->getAsmOperands()->getOperands()[index].mem;

    if(mem.index != INVALID_REGISTER) {
        setRegRead(X86Register::convertToPhysical(mem.index), instr);
    }

    if(mem.base != INVALID_REGISTER) {
        setRegRead(X86Register::convertToPhysical(mem.base), instr);
    }
}

#ifdef ARCH_X86_64
void ReachingDef::fillAddOrSub(Instruction *instr, AssemblyPtr assembly) {
    auto mode = assembly->getAsmOperands()->getMode();
    if(mode == AssemblyOperands::MODE_IMM_REG) {
        setRegWrite(getReg(assembly, 1), instr);
    }
    else if(mode == AssemblyOperands::MODE_REG_REG) {
        setRegRead(getReg(assembly, 0), instr);
        setRegWrite(getReg(assembly, 1), instr);
    }
    else if(mode == AssemblyOperands::MODE_MEM_REG) {
        handleMem(assembly, 0, instr);
        setRegWrite(getReg(assembly, 1), instr);
    }
    else {
        LOG(10, "skipping mode " << mode);
    }
}
void ReachingDef::fillAnd(Instruction *instr, AssemblyPtr assembly) {
    auto mode = assembly->getAsmOperands()->getMode();
    if(mode == AssemblyOperands::MODE_IMM_REG) {
        setRegWrite(getReg(assembly, 1), instr);
    }
    else {
        LOG(10, "skipping mode " << mode);
    }
}
void ReachingDef::fillBsf(Instruction *instr, AssemblyPtr assembly) {
    auto mode = assembly->getAsmOperands()->getMode();
    if(mode == AssemblyOperands::MODE_REG_REG) {
        setRegWrite(getReg(assembly, 0), instr);
        setRegRead(getReg(assembly, 1), instr);
    }
    else {
        LOG(10, "skipping mode " << mode);
    }
}
void ReachingDef::fillBt(Instruction *instr, AssemblyPtr assembly) {
    auto mode = assembly->getAsmOperands()->getMode();
    if(mode == AssemblyOperands::MODE_REG_REG) {
        setRegRead(getReg(assembly, 0), instr);
        setRegRead(getReg(assembly, 1), instr);
    }
    else if(mode == AssemblyOperands::MODE_MEM_REG) {
        handleMem(assembly, 0, instr);
        setRegRead(getReg(assembly, 1), instr);
    }
    else {
        LOG(10, "skipping mode " << mode);
    }
    setRegWrite(X86Register::FLAGS, instr);
}
void ReachingDef::fillCmp(Instruction *instr, AssemblyPtr assembly) {
    auto mode = assembly->getAsmOperands()->getMode();
    if(mode == AssemblyOperands::MODE_REG_REG) {
        setRegRead(getReg(assembly, 0), instr);
        setRegRead(getReg(assembly, 1), instr);
    }
    else if(mode == AssemblyOperands::MODE_IMM_REG) {
        setRegRead(getReg(assembly, 1), instr);
    }
    else if(mode == AssemblyOperands::MODE_IMM_MEM) {
        handleMem(assembly, 1, instr);
    }
    else {
        LOG(10, "skipping mode " << mode);
    }
    setRegWrite(X86Register::FLAGS, instr);
}
void ReachingDef::fillLea(Instruction *instr, AssemblyPtr assembly) {
    auto mode = assembly->getAsmOperands()->getMode();
    if(mode == AssemblyOperands::MODE_MEM_REG) {
        handleMem(assembly, 0, instr);
        setRegWrite(getReg(assembly, 1), instr);
    }
    else {
        LOG(10, "skipping mode " << mode);
    }
}
void ReachingDef::fillMov(Instruction *instr, AssemblyPtr assembly) {
    auto mode = assembly->getAsmOperands()->getMode();
    if(mode == AssemblyOperands::MODE_REG_MEM) {
        setRegRead(getReg(assembly, 0), instr);
        handleMem(assembly, 1, instr);
    }
    else if(mode == AssemblyOperands::MODE_MEM_REG) {
        handleMem(assembly, 0, instr);
        setRegWrite(getReg(assembly, 1), instr);
    }
    else if(mode == AssemblyOperands::MODE_REG_REG) {
        setRegRead(getReg(assembly, 0), instr);
        setRegWrite(getReg(assembly, 1), instr);
    }
    else {
        LOG(10, "skipping mode " << mode);
    }
}
void ReachingDef::fillMovabs(Instruction *instr, AssemblyPtr assembly) {
    auto mode = assembly->getAsmOperands()->getMode();
    assert(mode == AssemblyOperands::MODE_IMM_REG);
    if(mode == AssemblyOperands::MODE_IMM_REG) {
        setRegWrite(getReg(assembly, 1), instr);
    }
    else {
        LOG(10, "skipping mode " << mode);
    }
}
void ReachingDef::fillMovsxd(Instruction *instr, AssemblyPtr assembly) {
    fillMov(instr, assembly);
}
void ReachingDef::fillMovzx(Instruction *instr, AssemblyPtr assembly) {
    fillMov(instr, assembly);
}
void ReachingDef::fillPush(Instruction *instr, AssemblyPtr assembly) {
    auto mode = assembly->getAsmOperands()->getMode();
    if(mode == AssemblyOperands::MODE_REG) {
        setRegRead(getReg(assembly, 0), instr);
    }
    else if(mode == AssemblyOperands::MODE_MEM) {
        handleMem(assembly, 0, instr);
    }
    else {
        LOG(10, "skipping mode " << mode);
    }
    setRegWrite(X86Register::SP, instr);
}
void ReachingDef::fillPop(Instruction *instr, AssemblyPtr assembly) {
    auto mode = assembly->getAsmOperands()->getMode();
    if(mode == AssemblyOperands::MODE_REG) {
        setRegWrite(getReg(assembly, 0), instr);
    }
    else if(mode == AssemblyOperands::MODE_MEM) {
        handleMem(assembly, 0, instr);
    }
    else {
        LOG(10, "skipping mode " << mode);
    }
    setRegWrite(X86Register::SP, instr);
}
#endif
