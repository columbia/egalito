#include "resolverelocs.h"
#include "chunk/instruction.h"
#include "log/log.h"

void ResolveRelocs::visit(Instruction *instruction) {
    auto semantic = instruction->getSemantic();

    // look for instructions with Links
    if(auto v = dynamic_cast<ControlFlowInstruction *>(semantic)) {
        auto link = v->getLink();
        if(link && !link->getTarget()) {
            auto address = link->getTargetAddress();
            auto reloc = relocList->find(address);

            if(reloc) {
                LOG(0, "FOUND function call to " << address);
            }
            else {
                LOG(0, "UNKNOWN function call to " << address);
            }
        }
    }

    for(auto r : *relocList) {
        if(r->getType() == R_X86_64_JUMP_SLOT) {
            LOG(0, "reloc at " << r->getAddress() << " target " << r->getSymbol());
        }
    }
}
