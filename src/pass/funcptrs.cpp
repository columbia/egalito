#include "funcptrs.h"
#include "chunk/chunk.h"
#include "chunk/concrete.h"
#include "chunk/instruction.h"
#include "chunk/find.h"
#include "log/log.h"

void FuncptrsPass::visit(Module *module) {
    auto children = module->getChildren();
    if(!children->getNamed()) children->createNamed();

    for(auto r : *relocList) {
        if(!r->getSymbol()) continue;

        Function *target = children->getNamed()->find(r->getSymbol()->getName());
        if(!target) continue;

        // we know r is inside this module, but we don't know where yet
        handleRelocation(r, module, target);
    }
}

void FuncptrsPass::handleRelocation(Reloc *r, Module *module, Function *target) {
    Chunk *inner = ChunkFind().findInnermostInsideInstruction(module, r->getAddress());
    if(auto i = dynamic_cast<Instruction *>(inner)) {
        LOG0(2, "reloc inside " << i->getName() << " at "
            << r->getAddress() << " targets [" << target->getName() << "]");

        if(auto v = dynamic_cast<DisassembledInstruction *>(i->getSemantic())) {
            auto ri = new RelocationInstruction(DisassembledStorage(*v->getCapstone()));
            ri->setLink(new NormalLink(target));
            i->setSemantic(ri);
            LOG(2, " -> CREATED LINK for funcptr");
        }
        else {
            // note: if it's a ControlFlowInstruction, we don't need to do
            // anything here because the ResolveCalls pass deals with it
            LOG(2, "");
        }
    }
}
