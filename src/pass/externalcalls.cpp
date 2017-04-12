#include "externalcalls.h"
#include "instr/concrete.h"

#undef DEBUG_GROUP
#define DEBUG_GROUP dplt
#include "log/log.h"

void ExternalCalls::visit(Instruction *instruction) {
    auto semantic = instruction->getSemantic();

    // look for instructions with Links
    if(auto v = dynamic_cast<ControlFlowInstruction *>(semantic)) {
        auto link = v->getLink();
        if(link && !link->getTarget()) {
            auto address = link->getTargetAddress();
            auto pltEntry = CIter::spatial(pltList)->find(address);

            if(pltEntry) {
                LOG(1, "plt call at 0x" << std::hex << instruction->getAddress()
                    << " to 0x" << address
                    << " i.e. [" << pltEntry->getName() << "]");
                v->setLink(new PLTLink(address, pltEntry));
                delete link;
            }
        }
    }
}
