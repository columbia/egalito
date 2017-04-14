#ifndef EGALITO_PASS_JUMP_TABLE_BOUNDS_H
#define EGALITO_PASS_JUMP_TABLE_BOUNDS_H

#include <map>
#include "chunkpass.h"

/** Uses relocations and jump table beginning points to infer the number of
    entries in jump tables. Only works on modules compiled with -Wl,-q. Based
    on Shuffler's technique.
*/
class JumpTableBounds : public ChunkPass {
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
