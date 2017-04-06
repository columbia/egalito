#ifndef EGALITO_PASS_STACKXOR_H
#define EGALITO_PASS_STACKXOR_H

#include "chunkpass.h"
#include "chunk/concrete.h"

class StackXOR : public ChunkPass {
private:
    int xorOffset;
public:
    StackXOR(int xorOffset) : xorOffset(xorOffset) {}
    virtual void visit(Function *function);
    virtual void visit(Block *block);
    virtual void visit(Instruction *instruction);
private:
    void addInstructions(Block *block, Instruction *instruction);
};

#endif
