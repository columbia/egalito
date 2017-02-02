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

            if(address && *reinterpret_cast<unsigned short *>(address) == 0x25ff) {
                address_t got_location
                    = *(unsigned int *)(address + 2)  // +2 to get to addr
                    + address + 2+4;  // +2+4 to skip jmpq instruction
                LOG(0, "plt call at " << instruction->getAddress() << ", suspect got at " << got_location);
                auto found = pltRegistry.find(got_location);
                if(found) {
                    LOG(0, "FOUND CORRESPONDING reloc! " << found);
                    v->setLink(new PLTLink(found));
                }
            }
        }
    }
}

void ResolveRelocs::buildRegistry() {
    for(auto r : *relocList) {
        if(r->getType() == R_X86_64_JUMP_SLOT) {
            LOG(0, "register reloc at " << r->getAddress() << " target " << r->getSymbol());
            pltRegistry.add(r->getAddress(), r);
        }
    }
}
