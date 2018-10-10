#include "clearplts.h"

void ClearPLTs::visit(Module *module) {
    recurse(module->getPLTList());
}

void ClearPLTs::visit(PLTTrampoline *plt) {
    if(!clearIFuncs && plt->isIFunc()) return;

    freeChildren(plt, 2);
}

void ClearPLTs::freeChildren(Chunk *chunk, int level) {
    if(level > 0) {
        for(int i = chunk->getChildren()->genericGetSize() - 1; i >= 0; i --) {
            auto child = chunk->getChildren()->genericGetAt(i);
            freeChildren(child, level-1);
            chunk->getChildren()->genericRemoveLast();
            delete child;
        }
    }
}
