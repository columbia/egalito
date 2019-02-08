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
    virtual void visit(VTableList *vtable);
    virtual void visit(InitFunctionList *initFunctionList);
    virtual void visit(ExternalSymbolList *externalSymbolList);
    virtual void visit(LibraryList *libraryList);
    virtual void visit(Function *function);
    virtual void visit(Block *block);
    virtual void visit(Instruction *instruction);
    virtual void visit(PLTTrampoline *trampoline);
    virtual void visit(JumpTable *jumpTable);
    virtual void visit(JumpTableEntry *jumpTableEntry);
    virtual void visit(DataRegion *dataRegion);
    virtual void visit(DataSection *dataSection);
    virtual void visit(DataVariable *dataVariable);
    virtual void visit(GlobalVariable *globalVariable);
    virtual void visit(MarkerList *markerList);
    virtual void visit(VTable *vtable);
    virtual void visit(VTableEntry *vtableEntry);
    virtual void visit(InitFunction *initFunction);
    virtual void visit(ExternalSymbol *externalSymbol);
    virtual void visit(Library *library);
};

class InstrDumper : public InstructionVisitor {
private:
    address_t address;
    int pos;
public:
    InstrDumper(address_t address, int pos) : address(address), pos(pos) {}

    virtual void visit(IsolatedInstruction *semantic);
    virtual void visit(LinkedInstruction *semantic);
    virtual void visit(ControlFlowInstruction *semantic);
#ifdef ARCH_X86_64
    virtual void visit(DataLinkedControlFlowInstruction *semantic);
#endif
    virtual void visit(IndirectJumpInstruction *semantic);
    virtual void visit(IndirectCallInstruction *semantic);
    virtual void visit(StackFrameInstruction *semantic);
    virtual void visit(LiteralInstruction *semantic);
    virtual void visit(LinkedLiteralInstruction *semantic);
private:
    void dumpLinkedBase(LinkedInstructionBase *semantic, bool isCF);
    void dumpControlFlow(ControlFlowInstructionBase *semantic, bool printStar);
    std::string getBytes(InstructionSemantic *semantic);
};

#endif
