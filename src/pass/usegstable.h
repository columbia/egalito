#ifndef EGALITO_PASS_USE_GS_TABLE_H
#define EGALITO_PASS_USE_GS_TABLE_H

#include <map>
#include "chunkpass.h"
#include "chunk/link.h"
#include "chunk/gstable.h"

class UseGSTablePass : public ChunkPass {
private:
    Conductor *conductor;
    GSTable *gsTable;
    bool transformDirectCalls;
    bool transformIndirectCalls;
public:
    UseGSTablePass(Conductor *conductor, GSTable *gsTable,
        bool transformDirectCalls = true)
        : conductor(conductor), gsTable(gsTable),
        transformDirectCalls(transformDirectCalls),
        transformIndirectCalls(true) {}

private:
    virtual void visit(Module *module);
    virtual void visit(Function *function);
    virtual void visit(Block *block);
    virtual void visit(DataRegion *dataRegion);
    virtual void visit(PLTTrampoline *trampoline);
    virtual void visit(VTable *vtable);
    virtual void visit(VTableEntry *vtableEntry);

    void redirectLinks(Instruction *instr);
    void redirectFunctionPointerLinks(DataVariable *var);
    void rewriteDirectCall(Block *block, Instruction *instr);
    void rewriteTailRecursion(Block *block, Instruction *instr);
    void rewriteIndirectCall(Block *block, Instruction *instr);
    void rewriteIndirectTailRecursion(Block *block, Instruction *instr);
    void rewriteRIPrelativeCall(Block *block, Instruction *instr);
    void rewriteRIPrelativeJump(Block *block, Instruction *instr);
};

#endif
