#ifndef EGALITO_PASS_DUMP_TLS_INSTR_H
#define EGALITO_PASS_DUMP_TLS_INSTR_H

#include "chunkpass.h"

class DumpTLSInstrPass : public ChunkPass {
public:
    virtual void visit(Instruction *instruction);
};

#endif
