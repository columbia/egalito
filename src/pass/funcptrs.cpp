#include "funcptrs.h"
#include "elf/elfspace.h"
#include "chunk/chunk.h"
#include "chunk/concrete.h"
#include "chunk/dump.h"
#include "operation/find.h"
#include "instr/concrete.h"
#include "disasm/makesemantic.h"
#include "log/log.h"

void FuncptrsPass::visit(Module *module) {
    this->module = module;
    auto functionList = module->getFunctionList();
    for(auto r : *relocList) {
        if(!r->getSymbol()) continue;

        Function *target = CIter::findChild(functionList,
            r->getSymbol()->getName());

        if(!target) {
            if (module->getElfSpace()->getElfMap()->isObjectFile()) {
                handleRelocation(r, functionList, r->getSymbol());
            }
            continue;
        }

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
            auto assembly = v->getAssembly();
            if(!assembly) return;
            auto linked = LinkedInstruction::makeLinked(module, i, assembly);
            if(linked) {
                i->setSemantic(linked);
                delete v;
            }
#if 0
            for(size_t op = 0;
                op < v->getAssembly()->getAsmOperands()->getOpCount();
                op ++) {

                if(MakeSemantic::isRIPRelative(v->getAssembly(), op)) {
                    auto ri = new LinkedInstruction(i, *v->getAssembly(), op);
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
#endif
#else
            if(r->getType() != R_AARCH64_ADR_GOT_PAGE
               && r->getType() != R_AARCH64_LD64_GOT_LO12_NC) {
                auto ri = new LinkedInstruction(i, *v->getAssembly());
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

void FuncptrsPass::handleRelocation(Reloc *r, FunctionList *functionList,
                                    Symbol *symbol) {

    Chunk *inner = ChunkFind().findInnermostInsideInstruction(functionList, r->getAddress());
    if (inner){
        if(auto i = dynamic_cast<Instruction *>(inner)) {
            if(auto v = dynamic_cast<ControlFlowInstruction *>(i->getSemantic())) {
                auto oldLink = v->getLink();

                // Symbol Only links should only be formed with relocations for object files where symbol is in UND section (0)
                if(symbol->getSectionIndex() == 0) {
                    auto newLink = new SymbolOnlyLink(symbol, r->getAddress());
                    v->setLink(newLink);
                    LOG(2, " -> CREATED SYMBOL ONLY LINK");
                    delete oldLink;
                }
            }
            else if(auto v = dynamic_cast<DisassembledInstruction *>(i->getSemantic())) {
                auto assembly = v->getAssembly();
                if(!assembly) return;

                auto linked = new LinkedInstruction(i, *assembly);
                i->setSemantic(linked);
                delete v;

                auto elfMap = module->getElfSpace()->getElfMap();
                auto targetAddress = r->getSymbol()->getAddress() + r->getAddend();

                for(size_t op = 0;
                    op < linked->getAssembly()->getAsmOperands()->getOpCount();
                    op ++) {
                    int opOffset = MakeSemantic::getDispOffset(linked->getAssembly(), op);
                    if (r->getAddress() - i->getAddress() == (address_t)opOffset) {
                        linked->setIndex(op);
                    }
                }

                if (MakeSemantic::isRIPRelative(linked->getAssembly(), linked->getIndex())) {
                    linked->setLink(new DataOffsetLink(elfMap, targetAddress));
                } else {
                    linked->setLink(new AbsoluteDataLink(elfMap, targetAddress));
                }

                LOG(2, " -> CREATED DATA LINK");
            }
        }
    }
}
