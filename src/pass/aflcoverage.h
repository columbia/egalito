#ifndef EGALITO_PASS_AFL_COVERAGE_H
#define EGALITO_PASS_AFL_COVERAGE_H

#include "chunkpass.h"

class AFLCoveragePass : public ChunkPass {
private:
    Function *entryPoint;
    unsigned long blockID;
public:
    AFLCoveragePass() : blockID(1) {}
    virtual void visit(Program *program);
    virtual void visit(Module *module);
    virtual void visit(Function *function);
    virtual void visit(Block *block);
private:
    void addCoverageCode(Block *block);
};


#endif
