#ifndef EGALITO_ANALYSIS_REACHING_DEF_H
#define EGALITO_ANALYSIS_REACHING_DEF_H

#include <map>
#include <set>
#include <functional>
#include "instr/assembly.h"

class Block;
class Instruction;

/** This is a fairly limited analysis that is limited to basic blocks and
    is conservative for unknown instructions. UseDef operates independently.
*/
class ReachingDef {
public:
    typedef void (ReachingDef::*HandlerType)(Instruction *instr,
        AssemblyPtr assembly);
    typedef std::function<Instruction *(const std::vector<Instruction *> &)>
        VisitCallback;
private:
    Block *block;

    // maps from register writes to list of reads/writes killed (partial order)
    std::map<Instruction *, std::set<Instruction *>> killMap;

    // list of instructions that cannot be moved (depend on all prev instrs)
    ////std::set<Instruction *> barrierList;

    std::map<int, std::set<Instruction *>> currentAccessMap;

    const static std::map<int, HandlerType> handlers;
public:
    ReachingDef(Block *block) : block(block) {}
    void analyze();

    void visitInstructionGroups(VisitCallback callback);

    void dump();
private:
    bool areDependenciesCovered(Instruction *instr,
        const std::set<Instruction *> &covered);
    void setBarrier(Instruction *instr);

    void setRegRead(int reg, Instruction *instr);
    void setRegWrite(int reg, Instruction *instr);
    int getReg(AssemblyPtr assembly, int index);
    void handleMem(AssemblyPtr assembly, int index, Instruction *instr);

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
#endif
};

#endif
