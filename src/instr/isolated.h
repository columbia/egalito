#ifndef EGALITO_INSTR_ISOLATED_H
#define EGALITO_INSTR_ISOLATED_H

#include "semantic.h"

typedef SemanticImpl<RawByteStorage> RawInstruction;
typedef SemanticImpl<DisassembledStorage> DisassembledInstruction;

typedef DisassembledInstruction IsolatedInstruction;

#endif
