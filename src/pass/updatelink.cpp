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
    if(dynamic_cast<LinkedInstruction *>(s)
        || dynamic_cast<ControlFlowInstruction *>(s)) {

        auto oldLink = s->getLink();
        if(auto link = makeUpdateLink(oldLink, nullptr)) {
            LOG(10, " from I " << std::hex << instruction->getAddress());
            s->setLink(link);
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
                link2 = new NormalLink(targetFunction,
                    Link::SCOPE_INTERNAL_JUMP);
            }
            else {
                link2 = new NormalLink(targetFunction,
                    Link::SCOPE_EXTERNAL_JUMP);
            }
        }
    }

    return link2;
}
