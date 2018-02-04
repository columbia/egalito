#include <cassert>
#include <algorithm>
#include <queue>
#include "reachingdef.h"
#include "chunk/concrete.h"
#include "chunk/dump.h"
#include "instr/concrete.h"
#include "instr/register.h"

#undef DEBUG_GROUP
#define DEBUG_GROUP dreorder
#include "log/log.h"

#ifdef ARCH_X86_64
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
            assert(available.empty());
            break;
        }

        auto chosen = callback(std::move(group));
        available.erase(available.find(chosen));
        visited.insert(chosen);
    }
}

void ReachingDef::computeDependencyClosure(bool allowPushReordering) {
    std::map<Instruction *, std::set<Instruction *>> newKillMap;

    for(auto source : CIter::children(block)) {
        for(auto dest : CIter::children(block)) {
            if(allowPushReordering && bothPushesOrPops(source, dest)) continue;

            if(inKillClosure(source, dest)) {
                newKillMap[source].insert(dest);
            }
        }
    }

    killMap = std::move(newKillMap);
    dependencyClosure = true;
}

bool ReachingDef::inKillClosure(Instruction *source, Instruction *dest) {
    std::queue<Instruction *> queue;
    queue.push(source);

    std::set<Instruction *> visited;
    visited.insert(source);

    do {
        Instruction *i = queue.front();
        queue.pop();
        visited.insert(i);

        auto &set = killMap[i];
        if(set.find(dest) != set.end()) return true;

        for(auto newInstr : set) {
            if(visited.find(newInstr) == visited.end()) {
                queue.push(newInstr);
            }
        }
    } while(!queue.empty());

    return false;
}

bool ReachingDef::areDependenciesCovered(Instruction *instr,
    const std::set<Instruction *> &covered) {

    for(const auto &dependency : killMap[instr]) {
        if(covered.find(dependency) == covered.end()) return false;
        if(!dependencyClosure && !areDependenciesCovered(dependency, covered)) {
            return false;
        }
    }

    return true;
}

void ReachingDef::setBarrier(Instruction *instr) {
    for(Chunk *c = instr->getPreviousSibling(); c; c = c->getPreviousSibling()) {
        assert(instr != c);
        if(auto v = dynamic_cast<Instruction *>(c)) {
            killMap[instr].insert(v);
        }
    }

    // <= to include MEMORY_REG
    for(int r = 0; r <= X86Register::REGISTER_NUMBER + 1; r ++) {
        currentWriteMap[r] = { instr };
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
            LOG0(1, "    kills    " << kill->getName() << ", ");
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
    {X86_INS_MOVD,      &ReachingDef::fillMov},
    {X86_INS_MOVQ,      &ReachingDef::fillMov},
    {X86_INS_MOVABS,    &ReachingDef::fillMovabs},
    {X86_INS_MOVSXD,    &ReachingDef::fillMovsxd},
    {X86_INS_MOVZX,     &ReachingDef::fillMovzx},
    {X86_INS_PUSH,      &ReachingDef::fillPush},
    {X86_INS_POP,       &ReachingDef::fillPop},
    {X86_INS_SUB,       &ReachingDef::fillAddOrSub},
    {X86_INS_XOR,       &ReachingDef::fillAddOrSub},
#endif
};

void ReachingDef::setRegRead(int reg, Instruction *instr) {
    auto it = currentWriteMap.find(reg);
    if(it != currentWriteMap.end() && (*it).second != instr) {
        killMap[instr].insert((*it).second);
    }
    currentReadMap[reg].insert(instr);
}

void ReachingDef::setRegWrite(int reg, Instruction *instr) {
    auto it = currentWriteMap.find(reg);
    if(it != currentWriteMap.end()) {
        killMap[instr].insert((*it).second);
    }

    // avoid self-loops e.g. xor %eax, %eax
    auto it2 = currentReadMap[reg].find(instr);
    if(it2 != currentReadMap[reg].end()) {
        currentReadMap[reg].erase(it2);
    }

    killMap[instr].insert(
        currentReadMap[reg].begin(), currentReadMap[reg].end());
    for(auto i : killMap[instr]) {
        assert(i != instr);
    }

    currentWriteMap[reg] = instr;
    currentReadMap[reg].clear();
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

void ReachingDef::setMemRead(Instruction *instr) {
    setRegRead(MEMORY_REG, instr);
}

void ReachingDef::setMemWrite(Instruction *instr) {
    setRegWrite(MEMORY_REG, instr);
}

#ifdef ARCH_X86_64
void ReachingDef::fillAddOrSub(Instruction *instr, AssemblyPtr assembly) {
    auto mode = assembly->getAsmOperands()->getMode();
    if(mode == AssemblyOperands::MODE_IMM_REG) {
        setRegWrite(getReg(assembly, 1), instr);
        setRegWrite(X86Register::FLAGS, instr);
    }
    else if(mode == AssemblyOperands::MODE_REG_REG) {
        setRegRead(getReg(assembly, 0), instr);
        setRegWrite(getReg(assembly, 1), instr);
        setRegWrite(X86Register::FLAGS, instr);
    }
    else if(mode == AssemblyOperands::MODE_MEM_REG) {
        handleMem(assembly, 0, instr);
        setRegWrite(getReg(assembly, 1), instr);
        setMemWrite(instr);
        setRegWrite(X86Register::FLAGS, instr);
    }
    else {
        setBarrier(instr);
        LOG(10, "skipping mode " << mode);
    }
}
void ReachingDef::fillAnd(Instruction *instr, AssemblyPtr assembly) {
    auto mode = assembly->getAsmOperands()->getMode();
    if(mode == AssemblyOperands::MODE_IMM_REG) {
        setRegWrite(getReg(assembly, 1), instr);
        setRegWrite(X86Register::FLAGS, instr);
    }
    else {
        setBarrier(instr);
        LOG(10, "skipping mode " << mode);
    }
}
void ReachingDef::fillBsf(Instruction *instr, AssemblyPtr assembly) {
    auto mode = assembly->getAsmOperands()->getMode();
    if(mode == AssemblyOperands::MODE_REG_REG) {
        setRegWrite(getReg(assembly, 0), instr);
        setRegRead(getReg(assembly, 1), instr);
        setRegWrite(X86Register::FLAGS, instr);
    }
    else {
        setBarrier(instr);
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
        setMemWrite(instr);
    }
    else {
        setBarrier(instr);
        LOG(10, "skipping mode " << mode);
    }
    setRegWrite(X86Register::FLAGS, instr);
}
void ReachingDef::fillCmp(Instruction *instr, AssemblyPtr assembly) {
    auto mode = assembly->getAsmOperands()->getMode();
    if(mode == AssemblyOperands::MODE_REG_REG) {
        setRegRead(getReg(assembly, 0), instr);
        setRegRead(getReg(assembly, 1), instr);
        setRegWrite(X86Register::FLAGS, instr);
    }
    else if(mode == AssemblyOperands::MODE_IMM_REG) {
        setRegRead(getReg(assembly, 1), instr);
        setRegWrite(X86Register::FLAGS, instr);
    }
    else if(mode == AssemblyOperands::MODE_IMM_MEM) {
        handleMem(assembly, 1, instr);
        setMemRead(instr);
        setRegWrite(X86Register::FLAGS, instr);
    }
    else {
        setBarrier(instr);
        LOG(10, "skipping mode " << mode);
    }
}
void ReachingDef::fillLea(Instruction *instr, AssemblyPtr assembly) {
    auto mode = assembly->getAsmOperands()->getMode();
    if(mode == AssemblyOperands::MODE_MEM_REG) {
        handleMem(assembly, 0, instr);
        setRegWrite(getReg(assembly, 1), instr);
    }
    else {
        setBarrier(instr);
        LOG(10, "skipping mode " << mode);
    }
}
void ReachingDef::fillMov(Instruction *instr, AssemblyPtr assembly) {
    auto mode = assembly->getAsmOperands()->getMode();
    if(mode == AssemblyOperands::MODE_IMM_REG) {
        setRegWrite(getReg(assembly, 1), instr);
    }
    else if(mode == AssemblyOperands::MODE_REG_MEM) {
        setRegRead(getReg(assembly, 0), instr);
        handleMem(assembly, 1, instr);
        setMemWrite(instr);
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
        setBarrier(instr);
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
        setBarrier(instr);
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
        setBarrier(instr);
        LOG(10, "skipping mode " << mode);
    }
    setMemWrite(instr);
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
        setBarrier(instr);
        LOG(10, "skipping mode " << mode);
    }
    setMemRead(instr);
    setRegWrite(X86Register::SP, instr);
}
#endif

bool ReachingDef::bothPushesOrPops(Instruction *one, Instruction *two) {
    auto asm1 = one->getSemantic()->getAssembly();
    auto asm2 = two->getSemantic()->getAssembly();
    if(asm1 && asm2) {
        if(asm1->getId() == X86_INS_PUSH || asm1->getId() == X86_INS_POP) {
            if(asm1->getId() == asm2->getId()) return true;
        }
    }

    return false;
}
#endif
