#ifndef EGALITO_CHUNK_DUMP_H
#define EGALITO_CHUNK_DUMP_H

#include "chunk.h"
#include "concrete.h"
#include "instr/visitor.h"
#include "instr/concrete.h"
#include "visitor.h"

class ChunkDumper : public ChunkVisitor {
private:
    bool showBasicBlocks;
private:
    template <typename Type>
    void recurse(Type *root) {
        for(auto child : root->getChildren()->genericIterable()) {
            child->accept(this);
        }
    }
public:
    ChunkDumper(bool showBasicBlocks = true)
        : showBasicBlocks(showBasicBlocks) {}
    virtual void visit(Program *program) { recurse(program); }
    virtual void visit(Module *module);
    virtual void visit(FunctionList *functionList);
    virtual void visit(PLTList *pltList);
    virtual void visit(JumpTableList *jumpTableList);
    virtual void visit(DataRegionList *dataRegionList);
    virtual void visit(Function *function);
    virtual void visit(Block *block);
    virtual void visit(Instruction *instruction);
    virtual void visit(PLTTrampoline *trampoline);
    virtual void visit(JumpTable *jumpTable);
    virtual void visit(JumpTableEntry *jumpTableEntry);
    virtual void visit(DataRegion *dataRegion);
    virtual void visit(MarkerList *markerList);
};

class InstrDumper : public InstructionVisitor {
private:
    address_t address;
    int pos;
public:
    InstrDumper(address_t address, int pos) : address(address), pos(pos) {}

    virtual void visit(RawInstruction *semantic);
    virtual void visit(IsolatedInstruction *semantic);
    virtual void visit(LinkedInstruction *semantic);
    virtual void visit(ControlFlowInstruction *semantic);
    virtual void visit(IndirectJumpInstruction *semantic);
    virtual void visit(IndirectCallInstruction *semantic);
    virtual void visit(StackFrameInstruction *semantic);
    virtual void visit(LiteralInstruction *semantic);
    virtual void visit(LinkedLiteralInstruction *semantic);
private:
    std::string getBytes(InstructionSemantic *semantic);
};

#endif
