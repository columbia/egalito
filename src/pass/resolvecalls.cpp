#include <iostream>
#include "resolvecalls.h"
#include "chunk/find.h"
#include "log/log.h"

void ResolveCalls::visit(Module *module) {
    if(!module->getChildren()->getSpatial()) {
        module->getChildren()->createSpatial();
    }
    functionList = module->getChildren()->getSpatial();
    recurse(module);
}

void ResolveCalls::visit(Instruction *instruction) {
    auto semantic = instruction->getSemantic();
    auto link = semantic->getLink();
    if(!link) return;  // no link in this instruction
    if(link->getTarget()) return;  // link already resolved

    // We are only resolving ControlFlowInstruction targets
    if(!dynamic_cast<ControlFlowInstruction *>(semantic)) return;

    LOG0(1, "Looking up target 0x" << std::hex << link->getTargetAddress() << " -> ");

    Chunk *found = nullptr;
    // Common case for call instructions: point at another function
    if(!found) {
        found = functionList->find(link->getTargetAddress());
    }
    // Common case for jumps: internal jump elsewhere within function
    if(!found) {
        auto enclosing = instruction->getParent()->getParent();
        auto func = dynamic_cast<Function *>(enclosing);
        found = ChunkFind().findInnermostAt(func, link->getTargetAddress());
    }

    if(found) {
        LOG(1, "FOUND [" << found->getName() << "]");
        semantic->setLink(new NormalLink(found));
        delete link;
    }
    else {
        LOG(1, "NOT FOUND!");
    }
}
