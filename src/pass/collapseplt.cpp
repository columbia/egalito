#include <cassert>
#include "collapseplt.h"
#include "chunk/link.h"
#include "chunk/plt.h"
#include "instr/semantic.h"
#include "log/log.h"

void CollapsePLTPass::visit(Instruction *instr) {
    if(auto pltLink = dynamic_cast<PLTLink *>(instr->getSemantic()->getLink())) {
        auto trampoline = pltLink->getPLTTrampoline();

        if(trampoline->isIFunc()) return;  // we don't handle this yet

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
