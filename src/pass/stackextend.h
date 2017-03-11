#ifndef EGALITO_PASS_STACKEXTEND_H
#define EGALITO_PASS_STACKEXTEND_H

#include <vector>
#include <map>
#include <set>
#include "chunkpass.h"
#include "analysis/controlflow.h"
#include "chunk/register.h"
#include "elf/reloc.h"

class FrameType {
private:
    size_t baseSize;    // local varible + callee-saved regs
    size_t outArgSize;
    Instruction *setBPInstr;
    std::vector<Instruction *> resetSPInstrs;
    std::vector<Instruction *> returnInstrs;
public:
    FrameType(Function *function);
    Instruction *getSetBPInstr() const { return setBPInstr; }
    std::vector<Instruction *> getResetSPInstrs() const { return resetSPInstrs; }
    std::vector<Instruction *> getReturnInstrs() const { return returnInstrs; }
    void dump();

private:
    size_t getFrameSize(Function *function);
};

class StackExtendPass : public ChunkPass {
private:
    size_t extendSize;
public:
    StackExtendPass(size_t extendSize) : extendSize(extendSize) {}
    virtual void visit(Module *module);
    virtual void visit(Function *function);
    virtual void visit(Block *block) {}
    virtual void visit(Instruction *instruction) {}
private:
    bool shouldApply(Function *function);
    //change these names
    void extendStack(Function *function, FrameType *frame);
    virtual void useStack(Function *function, FrameType *frame) {};
    void shrinkStack(Function *function, FrameType *frame);
};

class RegisterUsage {
private:
    Function *function;
    Register regX;
    ControlFlowGraph cfg;

    std::map<Block *, std::vector<Instruction *>> UsageList;

    std::set<Register> incompatibleList;

    std::set<Block *> singleBlockList;
    std::set<Block *> rootBlockList;
    std::set<Block *> leafBlockList;

    bool categorized;

public:
    RegisterUsage(Function *function, Register x);
    const std::map<Block *, std::vector<Instruction *>> getUsage() const {
        return UsageList; }
    const std::set<Block *> getSingleBlockList() {
        if (!categorized) { categorizeBlocks(); } return singleBlockList; }
    const std::set<Block *> getRootBlockList() {
        if (!categorized) { categorizeBlocks(); } return rootBlockList; }
    const std::set<Block *> getLeafBlockList() {
        if (!categorized) { categorizeBlocks(); } return leafBlockList; }
    // in the extreme case, this has to be considered per instruction.
    Register getDualRegister(Block *block);
    std::vector<Instruction *> getInstructionList(Block *block) {
        return UsageList[block]; }
private:
    void categorizeBlocks();
};

class AARCH64InstructionBinary {
private:
    std::vector<unsigned char> v;
public:
    AARCH64InstructionBinary(uint32_t bin)
        : v({static_cast<unsigned char>(bin >> 0  & 0xff),
             static_cast<unsigned char>(bin >> 8  & 0xff),
             static_cast<unsigned char>(bin >> 16 & 0xff),
             static_cast<unsigned char>(bin >> 24 & 0xff)}) {}
    std::vector<unsigned char> getVector() { return v; }
};

#endif
