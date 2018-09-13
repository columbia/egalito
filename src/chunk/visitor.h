#ifndef EGALITO_CHUNK_VISITOR_H
#define EGALITO_CHUNK_VISITOR_H

#include "chunkfwd.h"

class ChunkVisitor {
public:
    virtual ~ChunkVisitor() {}
    virtual void visit(Program *program) = 0;
    virtual void visit(Module *module) = 0;
    virtual void visit(FunctionList *functionList) = 0;
    virtual void visit(PLTList *pltList) = 0;
    virtual void visit(JumpTableList *jumpTableList) = 0;
    virtual void visit(DataRegionList *dataRegionList) = 0;
    virtual void visit(VTableList *vtableList) = 0;
    virtual void visit(ExternalSymbolList *externalSymbolList) = 0;
    virtual void visit(LibraryList *libraryList) = 0;
    virtual void visit(Function *function) = 0;
    virtual void visit(Block *block) = 0;
    virtual void visit(Instruction *instruction) = 0;
    virtual void visit(PLTTrampoline *instruction) = 0;
    virtual void visit(JumpTable *jumpTable) = 0;
    virtual void visit(JumpTableEntry *jumpTableEntry) = 0;
    virtual void visit(DataRegion *dataRegion) = 0;
    virtual void visit(DataSection *dataSection) = 0;
    virtual void visit(DataVariable *dataVariable) = 0;
    virtual void visit(MarkerList *markerList) = 0;
    virtual void visit(VTable *vtable) = 0;
    virtual void visit(VTableEntry *vtableEntry) = 0;
    virtual void visit(ExternalSymbol *externalSymbol) = 0;
    virtual void visit(Library *library) = 0;
};
class ChunkListener : public ChunkVisitor {
public:
    virtual void visit(Program *program) {}
    virtual void visit(Module *module) {}
    virtual void visit(FunctionList *functionList) {}
    virtual void visit(PLTList *pltList) {}
    virtual void visit(JumpTableList *jumpTableList) {}
    virtual void visit(DataRegionList *dataRegionList) {}
    virtual void visit(VTableList *vtableList) {}
    virtual void visit(ExternalSymbolList *externalSymbolList) {}
    virtual void visit(LibraryList *libraryList) {}
    virtual void visit(Function *function) {}
    virtual void visit(Block *block) {}
    virtual void visit(Instruction *instruction) {}
    virtual void visit(PLTTrampoline *instruction) {}
    virtual void visit(JumpTable *jumpTable) {}
    virtual void visit(JumpTableEntry *jumpTableEntry) {}
    virtual void visit(DataRegion *dataRegion) {}
    virtual void visit(DataSection *dataSection) {}
    virtual void visit(DataVariable *dataVariable) {}
    virtual void visit(MarkerList *markerList) {}
    virtual void visit(VTable *vtable) {}
    virtual void visit(VTableEntry *vtableEntry) {}
    virtual void visit(ExternalSymbol *externalSymbol) {}
    virtual void visit(Library *library) {}
};

#endif
