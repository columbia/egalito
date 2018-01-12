#include <cassert>
#include "collapseplt.h"
#include "chunk/link.h"
#include "chunk/plt.h"
#include "instr/semantic.h"
#include "operation/find2.h"
#include "log/log.h"

CollapsePLTPass::CollapsePLTPass(Conductor *conductor)
    : conductor(conductor) {

    Function *function = nullptr;
#define KNOWN_IFUNC_ENTRY(name, target) \
    function = ChunkFind2(conductor).findFunction(#target); \
    ifuncMap.emplace(#name, function);

#include "../dep/ifunc/ifunc.h"

#undef KNOWN_IFUNC_ENTRY

    for(auto pair : ifuncMap) {
        assert(pair.second);
        LOG(1, "" << pair.first << " -> " << pair.second->getName());
    }
}

void CollapsePLTPass::visit(Instruction *instr) {
    if(auto pltLink
        = dynamic_cast<PLTLink *>(instr->getSemantic()->getLink())) {

        auto trampoline = pltLink->getPLTTrampoline();

        if(trampoline->isIFunc()) {
            auto name = trampoline->getExternalSymbol()->getName();
            auto it = ifuncMap.find(name);
            if(it != ifuncMap.end()) {
                LOG(10, "resolving IFunc " << name
                    << " as " << it->second->getName());
                instr->getSemantic()->setLink(
                    new NormalLink(it->second, Link::SCOPE_EXTERNAL_JUMP));
                delete pltLink;
            }
            else {
                LOG(1, "IFunc " << name << " will be resolve at runtime");
            }
            return;  // we don't handle this yet
        }

        if(auto target = trampoline->getTarget()) {
            instr->getSemantic()->setLink(
                new NormalLink(target, Link::SCOPE_EXTERNAL_JUMP));
            delete pltLink;
        }
        else {
            assert(trampoline->getExternalSymbol());
            LOG(9, "Unresolved PLT entry from " << instr->getName()
                << " to [" << trampoline->getExternalSymbol()->getName() << "]");
        }
    }
}
