#ifndef EGALITO_SHELL2_CHUNKS_H
#define EGALITO_SHELL2_CHUNKS_H

#include "code.h"
#include "command.h"
#include "conductor/interface.h"

class ChunkCommands {
private:
    FullCommandList *fullList;
public:
    ChunkCommands(FullCommandList *fullList) : fullList(fullList) {}
    void construct(EgalitoInterface *egalito);
};

#endif
