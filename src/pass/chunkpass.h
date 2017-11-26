#ifndef EGALITO_PASS_CHUNK_PASS_H
#define EGALITO_PASS_CHUNK_PASS_H

#include "chunk/chunk.h"
#include "chunk/concrete.h"
#include "chunk/visitor.h"
#include "util/timing.h"

#if 1  // enable pass profiling
    #define RUN_PASS(passConstructor, module) \
        { \
            EgalitoTiming timing(#passConstructor); \
            auto pass = passConstructor; \
            module->accept(&pass); \
        }
#else
    #define RUN_PASS(passConstructor, module) \
        { \
            auto pass = passConstructor; \
            module->accept(&pass); \
        }
#endif

class ChunkPass : public ChunkVisitor {
protected:
    template <typename Type>
    void recurse(Type *root) {
        for(auto child : root->getChildren()->genericIterable()) {
            child->accept(this);
        }
    }
public:
    virtual void visit(Program *program) { recurse(program); }
    virtual void visit(Module *module) { recurse(module); }
    virtual void visit(FunctionList *functionList) { recurse(functionList); }
    virtual void visit(PLTList *pltList) { recurse(pltList); }
    virtual void visit(JumpTableList *jumpTableList) { recurse(jumpTableList); }
    virtual void visit(DataRegionList *dataRegionList) { recurse(dataRegionList); }
    virtual void visit(VTableList *vtableList) { recurse(vtableList); }
    virtual void visit(Function *function) { recurse(function); }
    virtual void visit(Block *block) { recurse(block); }
    virtual void visit(Instruction *instruction) {}
    virtual void visit(PLTTrampoline *trampoline) {}
    virtual void visit(JumpTable *jumpTable) { recurse(jumpTable); }
    virtual void visit(JumpTableEntry *jumpTableEntry) {}
    virtual void visit(DataRegion *dataRegion) {}
    virtual void visit(MarkerList *markerList) {}
    virtual void visit(VTable *vtable) {}
    virtual void visit(VTableEntry *vtableEntry) {}
};

#endif
