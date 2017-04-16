#ifndef EGALITO_PASS_J_T_OVERESTIMATE_H
#define EGALITO_PASS_J_T_OVERESTIMATE_H

#include "chunkpass.h"

class JumpTableOverestimate : public ChunkPass {
private:
    Module *module;
    std::map<address_t, JumpTable *> tableMap;
public:
    virtual void visit(Module *module);
    virtual void visit(JumpTableList *jumpTableList);
    virtual void visit(JumpTable *jumpTable);
private:
    void setEntries(JumpTable *jumpTable, int count);
};

#endif
