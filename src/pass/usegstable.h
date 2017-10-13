#ifndef EGALITO_PASS_USE_GS_TABLE_H
#define EGALITO_PASS_USE_GS_TABLE_H

#include <map>
#include "chunkpass.h"
#include "chunk/link.h"
#include "chunk/gstable.h"

class UseGSTablePass : public ChunkPass {
private:
    GSTable *gsTable;
    bool transformDirectCalls;
public:
    UseGSTablePass(GSTable *gsTable, bool transformDirectCalls = true)
        : gsTable(gsTable), transformDirectCalls(transformDirectCalls) {}

    virtual void visit(Block *block);
private:
    void rewriteDirectCall(Block *block, Instruction *instr);
    void rewriteIndirectCall(Block *block, Instruction *instr);
};

#endif
