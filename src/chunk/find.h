#ifndef EGALITO_CHUNK_FIND_H
#define EGALITO_CHUNK_FIND_H

#include "types.h"
#include "chunk.h"
#include "concrete.h"  // for Instruction

class ChunkFind {
public:
    template <typename RootType>
    Chunk *findInnermostAt(RootType *root, address_t target);

    template <typename RootType>
    Chunk *findInnermostInsideInstruction(RootType *root, address_t target);
};

template <>
Chunk *ChunkFind::findInnermostAt(Instruction *root, address_t target);

template <typename RootType>
Chunk *ChunkFind::findInnermostAt(RootType *root, address_t target) {
    if(!root->getChildren()->getSpatial()) {
        root->getChildren()->createSpatial();
    }

    auto child = root->getChildren()->getSpatial()->findContaining(target);
    if(child) {
        return findInnermostAt(child, target);
    }

    return (root->getAddress() == target ? root : nullptr);
}

template <>
Chunk *ChunkFind::findInnermostInsideInstruction(Instruction *root, address_t target);

template <typename RootType>
Chunk *ChunkFind::findInnermostInsideInstruction(RootType *root, address_t target) {

    if(!root->getChildren()->getSpatial()) {
        root->getChildren()->createSpatial();
    }

    auto child = root->getChildren()->getSpatial()->findContaining(target);
    if(child) {
        return findInnermostInsideInstruction(child, target);
    }

    return (root->getAddress() == target ? root : nullptr);
}

#endif
