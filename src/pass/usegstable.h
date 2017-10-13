#ifndef EGALITO_PASS_USE_GS_TABLE_H
#define EGALITO_PASS_USE_GS_TABLE_H

#include <map>
#include "chunkpass.h"
#include "chunk/link.h"

class GSTable {
private:
    std::map<Function *, address_t> indexMap;
public:
    void assignIndex(Function *function);

    address_t getIndex(Function *function);
};

class GSTableLink : public Link {
private:
    ChunkRef target;
public:
    GSTableLink(ChunkRef target) : target(target) {}
    virtual ChunkRef getTarget() const { return target; }
    virtual address_t getTargetAddress() const;
};

class UseGSTablePass : public ChunkPass {
private:
    GSTable gs;
    bool transformDirectCalls;
public:
    UseGSTablePass(bool transformDirectCalls = true)
        : transformDirectCalls(transformDirectCalls) {}

    virtual void visit(Block *block);
private:
    void rewriteDirectCall(Block *block, Instruction *instr);
    void rewriteIndirectCall(Block *block, Instruction *instr);
};

#endif
