#include "updatelink.h"
#include "chunk/link.h"
#ifdef ARCH_X86_64
    #include "instr/linked-x86_64.h"
#endif
#ifdef ARCH_AARCH64
    #include "instr/linked-aarch64.h"
#endif
#include "log/log.h"

void UpdateLink::visit(Function *function) {
    sourceFunction = function;
    recurse(function);
}

void UpdateLink::visit(Instruction *instruction) {
    auto s = instruction->getSemantic();
    if(auto linked = dynamic_cast<LinkedInstruction *>(s)) {
        auto oldLink = linked->getLink();
        if(auto link = makeUpdateLink(oldLink, nullptr)) {
            LOG(10, " from I " << std::hex << instruction->getAddress());
            linked->setLink(link);
            delete oldLink;
        }
    }
}

void UpdateLink::visit(DataRegion *dataRegion) {
    for(auto var : dataRegion->variableIterable()) {
        auto oldLink = var->getDest();
        if(auto link = makeUpdateLink(oldLink, nullptr)) {
            LOG(10, " from D " << std::hex << var->getAddress());
            var->setDest(link);
            delete oldLink;
        }
    }
}

Link *UpdateLink::makeUpdateLink(Link *link, Function *source) {
    Link *link2 = nullptr;

    if(auto instr = dynamic_cast<Instruction *>(&*link->getTarget())) {
        auto targetFunction
            = static_cast<Function *>(instr->getParent()->getParent());
        if(targetFunction->getAddress() == instr->getAddress()) {
            LOG0(10, "updating link to " << targetFunction->getName());
            if(source && targetFunction == source) {
                link2 = new NormalLink(targetFunction);
            }
            else {
                link2 = new ExternalNormalLink(targetFunction);
            }
        }
    }

    return link2;
}
