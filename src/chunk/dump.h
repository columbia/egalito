#ifndef EGALITO_CHUNK_DUMP_H
#define EGALITO_CHUNK_DUMP_H

#include "chunk.h"
#include "concrete.h"
#include "instr/concrete.h"
#include "visitor.h"

class ChunkDumper : public ChunkVisitor {
private:
    template <typename Type>
    void recurse(Type *root) {
        for(auto child : root->getChildren()->genericIterable()) {
            child->accept(this);
        }
    }
public:
    virtual void visit(Program *program) {}
    virtual void visit(Module *module);
    virtual void visit(FunctionList *functionList);
    virtual void visit(BlockSoup *blockSoup);
    virtual void visit(PLTList *pltList);
    virtual void visit(Function *function);
    virtual void visit(Block *block);
    virtual void visit(Instruction *instruction);
    virtual void visit(PLTTrampoline *trampoline);
private:
    void dumpInstruction(ControlFlowInstruction *semantic,
                         address_t address, int pos);
#ifdef ARCH_AARCH64
    void dumpInstruction(PCRelativeInstruction *semantic,
                         address_t address, int pos);
#endif
    void dumpInstruction(LinkedInstruction *semantic,
                         address_t address, int pos);
    void dumpInstruction(IndirectJumpInstruction *semantic,
                         address_t address, int pos);
    void dumpInstruction(InstructionSemantic *semantic,
                         address_t address, int pos);
};

#endif
