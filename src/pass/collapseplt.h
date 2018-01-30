#ifndef EGALITO_PASS_COLLAPSE_PLT_H
#define EGALITO_PASS_COLLAPSE_PLT_H

#include <map>
#include "chunkpass.h"

class Conductor;
class Function;

class CollapsePLTPass : public ChunkPass {
private:
    Conductor *conductor;
    std::map<std::string, Function*> ifuncMap;
public:
    CollapsePLTPass(Conductor *conductor);
    virtual void visit(Module *module);
    virtual void visit(Instruction *instr);
    virtual void visit(DataSection *section);
};

#endif
