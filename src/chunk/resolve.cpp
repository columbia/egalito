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
#if 0
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
#elif 0
            RangeList blockList;
            for(auto b : enclosing->getChildren()->iterable()) {
                blockList.insert(
                    Range(b->getAddress(), b->getSize()),
                    b);
                std::cout << "insert [" << b->getAddress() << "," << b->getAddress() + b->getSize() << "]\n";
            }

            auto blockFound = blockList.overlapping(link->getTargetAddress());
            if(blockFound) {
                std::cout << "FOUND BLOCK [" << blockFound->first.getStart() << "," << blockFound->first.getEnd() << "]\n";

                semantic->setLink(new NormalLink(blockFound->second));
                delete link;
            }
            else std::cout << "...unknown\n";
#else
            ChunkOverlapSearch blockList;
            blockList.addChildren(enclosing);
            for(auto b : enclosing->getChildren()->iterable()) {
                std::cout << "insert [" << b->getAddress() << "," << b->getAddress() + b->getSize() << "]\n";
            }

            auto targetAddress = link->getTargetAddress();
            auto blockFound = blockList.find(Range::fromPoint(
                targetAddress));
            if(blockFound) {
                auto p = blockFound->getRange();
                std::cout << "FOUND BLOCK [" << p.getStart() << "," << p.getEnd() << "]\n";

                if(targetAddress == p.getStart()) {
                    semantic->setLink(new NormalLink(blockFound));
                    delete link;
                }
                else {
                    ChunkOverlapSearch instructionList;
                    instructionList.addChildren(dynamic_cast<Block *>(blockFound));
                    auto instructionFound = instructionList.find(Range::fromPoint(targetAddress));

                    if(instructionFound) {
                        semantic->setLink(new NormalLink(instructionFound));
                        delete link;
                    }
                    else {
                        std::cout << "Can't find exact instruction???\n";
                    }
                }
            }
            else std::cout << "...unknown\n";
#endif
        }
    }
}
