#include "chunk.h"

void Function::writeTo(Slot *slot) {
    for(auto block : blockList) {
        block->writeTo(slot);
    }
}

void Block::writeTo(Slot *slot) {
    
}
