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
            instr->getSemantic()->setLink(new ExternalNormalLink(target));
            delete pltLink;
        }
        else {
            assert(trampoline->getTargetSymbol());
            LOG(9, "Unresolved PLT entry from " << instr->getName()
                << " to [" << trampoline->getTargetSymbol()->getName() << "]");
        }
    }
}
