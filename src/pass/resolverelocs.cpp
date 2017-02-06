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
            auto pltEntry = pltSection->find(address);

            if(pltEntry) {
                LOG(0, "plt call at " << instruction->getAddress()
                    << " to " << address
                    << " i.e. [" << pltEntry->getName() << "]");
                v->setLink(new PLTLink(address, pltEntry));
                delete link;
            }
        }
    }
}
