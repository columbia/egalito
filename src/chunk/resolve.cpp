#include <iostream>
#include "resolve.h"

ChunkResolver::ChunkResolver(std::vector<Function *> &flist) {
    for(auto f : flist) {
        functionList.add(f);
    }
}

void ChunkResolver::visit(Instruction *instruction) {
    auto semantic = instruction->getSemantic();
    auto link = semantic->getLink();
    if(!link) return;

    if(!link->getTarget()) {
        std::cout << "looking up target 0x" << std::hex << link->getTargetAddress() << " -> ";
        auto found = functionList.find(link->getTargetAddress());
        if(found) {
            std::cout << "FOUND [" << found->getName() << "]\n";

            semantic->setLink(new NormalLink(found));
            delete link;
        }
        else {
            auto enclosing = dynamic_cast<Function *>(instruction->getParent()->getParent());
            SpatialChunkList<Block, ChunkList> blockList;
            for(auto b : enclosing->getChildren()->iterable()) {
                blockList.add(b);
            }

            auto blockFound = blockList.find(link->getTargetAddress());
            if(blockFound) {
                std::cout << "FOUND BLOCK\n";

                semantic->setLink(new NormalLink(blockFound));
                delete link;
            }
            else std::cout << "...unknown\n";
        }
    }
}
