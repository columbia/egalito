#include "funcptrs.h"
#include "chunk/chunk.h"
#include "chunk/concrete.h"
#include "operation/find.h"
#include "instr/concrete.h"
#include "disasm/makesemantic.h"
#include "log/log.h"

void FuncptrsPass::visit(Module *module) {
    auto functionList = module->getFunctionList();
    for(auto r : *relocList) {
        if(!r->getSymbol()) continue;

        Function *target = CIter::findChild(functionList,
            r->getSymbol()->getName());
        if(!target) continue;

        // we know r is inside this module, but we don't know where yet
        handleRelocation(r, functionList, target);
    }
}

void FuncptrsPass::handleRelocation(Reloc *r, FunctionList *functionList,
    Function *target) {

    Chunk *inner = ChunkFind().findInnermostInsideInstruction(functionList, r->getAddress());
    if(auto i = dynamic_cast<Instruction *>(inner)) {
        LOG0(2, "reloc inside " << i->getName() << " at "
            << r->getAddress() << " targets [" << target->getName() << "]");

        if(auto v = dynamic_cast<DisassembledInstruction *>(i->getSemantic())) {
#ifdef ARCH_X86_64
            for(size_t op = 0;
                op < v->getAssembly()->getAsmOperands()->getOpCount();
                op ++) {

                if(MakeSemantic::isRIPRelative(v->getAssembly(), op)) {
                    auto ri = new RelocationInstruction(i, *v->getAssembly(), op);
                    ri->setLink(new NormalLink(target));
                    i->setSemantic(ri);
                    LOG(2, " -> CREATED LINK for funcptr");
                    return;
                }
            }
            auto ri = new AbsoluteLinkedInstruction(i, *v->getAssembly(), 0);
            ri->setLink(new NormalLink(target));
            i->setSemantic(ri);
            LOG(2, " -> CREATED ABSOLUTE LINK for funcptr");
#else
            if(r->getType() != R_AARCH64_ADR_GOT_PAGE
               && r->getType() != R_AARCH64_LD64_GOT_LO12_NC) {
                auto ri = new RelocationInstruction(i, *v->getAssembly());
                ri->setLink(new NormalLink(target));
                i->setSemantic(ri);
                LOG(2, " -> CREATED LINK for funcptr");
            }
#endif
        }
        else {
            // note: if it's a ControlFlowInstruction, we don't need to do
            // anything here because the ResolveCalls pass deals with it
            LOG(2, "");
        }
    }
}
