#include "handlerelocs.h"
#include "elf/elfspace.h"
#include "chunk/chunk.h"
#include "chunk/concrete.h"
#include "chunk/dump.h"
#include "operation/find.h"
#include "instr/concrete.h"
#include "disasm/makesemantic.h"
#include "log/log.h"

void HandleRelocsPass::visit(Module *module) {
    this->module = module;
    auto functionList = module->getFunctionList();
    for(auto r : *relocList) {
        if(!r->getSymbol()) continue;

        Function *target = CIter::findChild(functionList,
            r->getSymbol()->getName());

        if(!target) {
            if(module->getElfSpace()->getElfMap()->isObjectFile()) {
                handleRelocation(r, functionList, r->getSymbol());
            }
            continue;
        }

        // we know r is inside this module, but we don't know where yet
        handleRelocation(r, functionList, target);
    }
}

void HandleRelocsPass::handleRelocation(Reloc *r, FunctionList *functionList,
    Function *target) {

    Chunk *inner = ChunkFind().findInnermostInsideInstruction(
        functionList, r->getAddress());

    if(auto i = dynamic_cast<Instruction *>(inner)) {
        if(dynamic_cast<ControlFlowInstruction *>(i->getSemantic())) {
            // we don't need to do anything here because the InternalCalls pass
            // and ExternalCalls pass deal with it
            return;
        }

        LOG(2, "reloc inside " << i->getName() << " at "
            << r->getAddress() << " targets [" << target->getName() << "]");
        if(auto v = dynamic_cast<DisassembledInstruction *>(i->getSemantic())) {
            auto assembly = v->getAssembly();
            if(!assembly) return;
#ifdef ARCH_X86_64
            auto linked = LinkedInstruction::makeLinked(module, i, assembly);
#else
            auto linked = LinkedInstruction::makeLinked(module, i, assembly, r);
#endif
            if(linked) {
                i->setSemantic(linked);
                delete v;
            }
        }
    }
}

void HandleRelocsPass::handleRelocation(Reloc *r, FunctionList *functionList,
    Symbol *symbol) {

#ifdef ARCH_X86_64
    Chunk *inner = ChunkFind().findInnermostInsideInstruction(
        functionList, r->getAddress());

    if(inner){
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

                auto targetAddress = r->getSymbol()->getAddress() + r->getAddend();

                for(size_t op = 0;
                    op < linked->getAssembly()->getAsmOperands()->getOpCount();
                    op ++) {
                    int opOffset = MakeSemantic::getDispOffset(linked->getAssembly(), op);
                    if(r->getAddress() - i->getAddress() == (address_t)opOffset) {
                        linked->setIndex(op);
                    }
                }

                bool isRelative = MakeSemantic::isRIPRelative(
                    linked->getAssembly(), linked->getIndex());
                auto newLink = module->getDataRegionList()->createDataLink(
                    targetAddress, isRelative);
                linked->setLink(newLink);

                LOG(2, " -> CREATED DATA LINK");
            }
        }
    }
#endif
}
