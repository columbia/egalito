#include "find.h"

template <>
Chunk *ChunkFind::findInnermostAt(Instruction *root, address_t target) {
    return (root->getAddress() == target ? root : nullptr);
}

template <>
Chunk *ChunkFind::findInnermostInsideInstruction(Instruction *root, address_t target) {
    return (root->getRange().contains(target) ? root : nullptr);
}


#if 0
Chunk *ChunkFind::find(Chunk *root, address_t targetAddress) {
    Chunk *found = findHelper(root, targetAddress);
    if(found) {
        std::cout << "resolved to " << found->getName() << std::endl;
    }
    else {
        std::cout << "???\n";
    }
    return found;
}

Chunk *ChunkFind::findHelper(Chunk *root, address_t targetAddress) {
    ChunkOverlapSearch chunkList;
    if(!root->getChildren()) return nullptr;

    for(auto chunk : root->getChildren()->genericIterable()) {
        chunkList.add(chunk);
    }

    auto found = chunkList.find(Range::fromPoint(targetAddress));
    if(found) {
        auto p = found->getRange();
        if(targetAddress == p.getStart()) {
            return found;
        }
        else {
            return findHelper(found, targetAddress);
        }
    }

    return nullptr;
}
#endif
