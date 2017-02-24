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

    auto targetAddress = link->getTargetAddress();

    // We are only resolving ControlFlowInstruction targets
    if(!dynamic_cast<ControlFlowInstruction *>(semantic)) return;

    LOG0(10, "Looking up target 0x" << std::hex << targetAddress << " -> ");

    Chunk *found = nullptr;
    // Common case for call instructions: point at another function
    if(!found) {
        found = functionList->find(targetAddress);
    }
    // Common case for jumps: internal jump elsewhere within function
    if(!found) {
        auto enclosing = instruction->getParent()->getParent();
        auto func = dynamic_cast<Function *>(enclosing);
#ifdef ARCH_X86_64
        // we get jumps into the middle of an instruction to skip "LOCK" prefix
        found = ChunkFind().findInnermostInsideInstruction(func, targetAddress);
#else
        found = ChunkFind().findInnermostAt(func, targetAddress);
#endif
    }
    // Uncommon case for jumps: external jump to another function
    // This can be for tail recursion or for overlapping functions (no_cancel)
    if(!found) {
        auto enclosing = instruction->getParent()->getParent()->getParent();
        auto module = dynamic_cast<Module *>(enclosing);

        // !!! right now, spatial search in a Module doesn't work...
        //found = ChunkFind().findInnermostAt(module, targetAddress);
        for(auto f : module->getChildren()->getIterable()->iterable()) {
            found = ChunkFind().findInnermostAt(f, targetAddress);
            // we could use a different Link type for external jumps
            if(found) break;
        }
    }

    if(found) {
        LOG(10, "FOUND [" << found->getName() << "]");
#ifdef ARCH_X86_64
        auto offset = targetAddress - found->getAddress();
        if(offset == 0) {
            semantic->setLink(new NormalLink(found));
        }
        else {
            auto i = dynamic_cast<Instruction *>(found);
            if(0 && i && offset == 1 && static_cast<unsigned char>(
                i->getSemantic()->getData()[0]) == 0xf0) {

                // jumping by skipping the "LOCK" prefix
                semantic->setLink(new OffsetLink(found, 1));
            }
            else {
                LOG(1, "WARNING: jumping into the middle of an instruction"
                    " in unknown manner!");
            }
        }
#else
        semantic->setLink(new NormalLink(found));
#endif
        delete link;
    }
    else {
        LOG(10, "NOT FOUND!");
    }
}
