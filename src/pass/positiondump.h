#ifndef EGALITO_PASS_POSITION_DUMP_H
#define EGALITO_PASS_POSITION_DUMP_H

#include "chunkpass.h"

class PositionDump {
public:
    void visit(Chunk *chunk, int indent = 1);
};

#endif
