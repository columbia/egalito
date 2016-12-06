#include <iostream>
#include "resolve.h"
#include "overlap.h"
#include "addressrange.h"

ChunkResolver::ChunkResolver(std::vector<Function *> &flist) {
    for(auto f : flist) {
        functionList.add(f);
    }
}

void ChunkResolver::visit(Instruction *instruction) {
    auto semantic = instruction->getSemantic();
    auto link = semantic->getLink();
    if(!link) return;  // no link in this instruction
    if(link->getTarget()) return;  // link already resolved

    std::cout << "looking up target 0x" << std::hex << link->getTargetAddress() << " -> ";
    auto found = functionList.find(link->getTargetAddress());
    if(found) {
        std::cout << "FOUND [" << found->getName() << "]\n";

        semantic->setLink(new NormalLink(found));
        delete link;
    }
    else {
        auto enclosing = instruction->getParent()->getParent();
        auto found = this->find(enclosing, link->getTargetAddress());
        if(found) {
            semantic->setLink(new NormalLink(found));
            delete link;
        }
        else {
            // target not known
        }
    }
}

Chunk *ChunkResolver::find(Chunk *root, address_t targetAddress) {
    Chunk *found = findHelper(root, targetAddress);
    if(found) {
        std::cout << "resolved to " << found->getName() << std::endl;
    }
    else {
        std::cout << "???\n";
    }
    return found;
}

Chunk *ChunkResolver::findHelper(Chunk *root, address_t targetAddress) {
    ChunkOverlapSearch chunkList;
    if(!root->getChildren()) return nullptr;

    auto it = root->getChildren()->genericIterator();
    while(it->hasNext()) {
        chunkList.add(it->next());
    }
    delete it;

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
