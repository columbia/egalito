#ifndef EGALITO_PASS_PROFILE_INSTRUMENT_H
#define EGALITO_PASS_PROFILE_INSTRUMENT_H

#include "chunkpass.h"
#include "chunk/dataregion.h"
#include "chunk/function.h"

class ProfileInstrumentPass : public ChunkPass {
public:
    virtual void visit(Function *function);
private:
    DataSection *createDataSection(Module *module);
    Link *addVariable(DataSection *section);
};

#endif
