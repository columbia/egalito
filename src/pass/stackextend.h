#ifndef EGALITO_PASS_STACKEXTEND_H
#define EGALITO_PASS_STACKEXTEND_H

#include "chunkpass.h"
#include "elf/reloc.h"

class Module;

class StackExtendPass : public ChunkPass {
private:
    size_t extendSize;
    struct frameType {
        size_t baseSize;    // local varible + callee-saved regs
        size_t outArgSize;
        Instruction *setBPInstr;
        std::vector<Instruction *>resetSPInstrs;
        std::vector<Instruction *>returnInstrs;
    };
public:
    StackExtendPass(size_t extendSize) : extendSize(extendSize) {}
    virtual void visit(Module *module);
    virtual void visit(Function *function);
    virtual void visit(Block *block) {}
    virtual void visit(Instruction *instruction) {}
private:
    bool shouldApply(Function *function);
    size_t getFrameSize(Function *function);
    void extendStack(Function *function, struct frameType *frame);
    void shrinkStack(Function *function, struct frameType *frame);
    void insertAt(Block *block, size_t index, Instruction *instr);
};

#endif
