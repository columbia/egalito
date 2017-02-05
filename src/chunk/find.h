#ifndef EGALITO_CHUNK_FIND_H
#define EGALITO_CHUNK_FIND_H

#include "types.h"
#include "chunk.h"
#include "concrete.h"  // for Instruction

class ChunkFind {
public:
    template <typename RootType>
    Chunk *findInnermostAt(RootType *root, address_t target)
        { return findImpl(root, target, false, false); }

    template <typename RootType>
    Chunk *findInnermostInsideInstruction(RootType *root, address_t target)
        { return findImpl(root, target, false, true); }

    template <typename RootType>
    Chunk *findInnermostContaining(RootType *root, address_t target)
        { return findImpl(root, target, true, true); }
private:
    template <typename RootType>
    Chunk *findImpl(RootType *root, address_t target,
        bool compositeContains, bool instructionContains);
};

template <>
Chunk *ChunkFind::findImpl(Instruction *root, address_t target,
    bool compositeContains, bool instructionContains);

template <typename RootType>
Chunk *ChunkFind::findImpl(RootType *root, address_t target,
    bool compositeContains, bool instructionContains) {

    if(!root->getChildren()->getSpatial()) {
        root->getChildren()->createSpatial();
    }

    auto child = root->getChildren()->getSpatial()->findContaining(target);
    if(child) {
        return findImpl(child, target, compositeContains, instructionContains);
    }

    if(!root->getPosition()) return nullptr;
    if(compositeContains) {
        return (root->getRange().contains(target) ? root : nullptr);
    }
    else {
        return (root->getAddress() == target ? root : nullptr);
    }
}

#endif
