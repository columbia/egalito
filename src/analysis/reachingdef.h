#ifndef EGALITO_ANALYSIS_REACHING_DEF_H
#define EGALITO_ANALYSIS_REACHING_DEF_H

#include <map>
#include <set>
#include <functional>
#include "instr/assembly.h"
#include "instr/register.h"

#ifdef ARCH_X86_64
class Block;
class Instruction;

/** This is a fairly limited analysis that is limited to basic blocks and
    is conservative for unknown instructions. UseDef operates independently.
*/
class ReachingDef {
public:
    typedef void (ReachingDef::*HandlerType)(Instruction *instr,
        AssemblyPtr assembly);
    typedef std::function<Instruction *(std::vector<Instruction *>)>
        VisitCallback;
private:
    Block *block;
    bool dependencyClosure;

    // maps from register writes to list of reads/writes killed (partial order)
    std::map<Instruction *, std::set<Instruction *>> killMap;

    // list of instructions that cannot be moved (depend on all prev instrs)
    ////std::set<Instruction *> barrierList;

    std::map<int, Instruction *> currentWriteMap;
    std::map<int, std::set<Instruction *>> currentReadMap;

    const static std::map<int, HandlerType> handlers;
    const static int MEMORY_REG = X86Register::REGISTER_NUMBER + 1;
    const static int MAX_REGS = MEMORY_REG + 1;
public:
    ReachingDef(Block *block) : block(block), dependencyClosure(false) {}
    void analyze();
    bool needsFlags();
    void computeDependencyClosure(bool allowPushReordering);

    void visitInstructionGroups(VisitCallback callback);

    void dump();
private:
    bool inKillClosure(Instruction *source, Instruction *dest);
    bool areDependenciesCovered(Instruction *instr,
        const std::set<Instruction *> &covered);
    void setBarrier(Instruction *instr);

    void setRegRead(int reg, Instruction *instr);
    void setRegWrite(int reg, Instruction *instr);
    int getReg(AssemblyPtr assembly, int index);
    void handleMem(AssemblyPtr assembly, int index, Instruction *instr);
    void setMemRead(Instruction *instr);
    void setMemWrite(Instruction *instr);

#ifdef ARCH_X86_64
    void fillAddOrSub(Instruction *instr, AssemblyPtr assembly);
    void fillAnd(Instruction *instr, AssemblyPtr assembly);
    void fillBsf(Instruction *instr, AssemblyPtr assembly);
    void fillBt(Instruction *instr, AssemblyPtr assembly);
    void fillCmp(Instruction *instr, AssemblyPtr assembly);
    void fillLea(Instruction *instr, AssemblyPtr assembly);
    void fillMov(Instruction *instr, AssemblyPtr assembly);
    void fillMovabs(Instruction *instr, AssemblyPtr assembly);
    void fillMovsxd(Instruction *instr, AssemblyPtr assembly);
    void fillMovzx(Instruction *instr, AssemblyPtr assembly);
    void fillPush(Instruction *instr, AssemblyPtr assembly);
    void fillPop(Instruction *instr, AssemblyPtr assembly);
    void fillTest(Instruction *instr, AssemblyPtr assembly);
    void fillNop(Instruction *instr, AssemblyPtr assembly);
    void fillCltq(Instruction *instr, AssemblyPtr assembly);
#endif

    bool bothPushesOrPops(Instruction *one, Instruction *two);
};

#endif

#endif
