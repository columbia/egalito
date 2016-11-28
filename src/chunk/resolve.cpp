#include <iostream>
#include "resolve.h"

void ChunkResolver::visit(Instruction *instruction) {
    auto semantic = instruction->getSemantic();
    auto link = semantic->getLink();
    if(!link) return;

    if(!link->getTarget()) {
        std::cout << "looking up target 0x" << std::hex << link->getTargetAddress() << std::endl;
    }
}
