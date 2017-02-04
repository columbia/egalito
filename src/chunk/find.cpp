#include "find.h"

template <>
Chunk *ChunkFind::findImpl(Instruction *root, address_t target,
    bool compositeContains, bool instructionContains) {

    if(instructionContains) {
        return (root->getRange().contains(target) ? root : nullptr);
    }
    else {
        return (root->getAddress() == target ? root : nullptr);
    }
}
