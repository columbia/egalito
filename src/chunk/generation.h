#ifndef EGALITO_GENERATION_H
#define EGALITO_GENERATION_H

#include <vector>
#include <memory>
#include "chunk.h"

class Generation {
private:
    std::unique_ptr<Sandbox> sandbox;

    typedef std::vector<std::shared_ptr<Chunk>> chunkListType;
    chunkListType chunkList;
public:
    //Generation(std::unique_ptr<Sandbox> sandbox) : sandbox(sandbox) {}

    void addChunk(Chunk *chunk);

    Sandbox *getSandbox() { return sandbox.get(); }
};

#endif
