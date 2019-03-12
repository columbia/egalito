#ifndef EGALITO_PASS_FIX_ENVIRON_H
#define EGALITO_PASS_FIX_ENVIRON_H

#include "chunkpass.h"

/** Add code to set __environ variable in _start, for uniongen only.
    This variable is normally set in _start for static executables.
*/
class FixEnvironPass : public ChunkPass {
public:
    virtual void visit(Program *program);
};

#endif
