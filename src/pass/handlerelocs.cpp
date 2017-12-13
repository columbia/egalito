#include "handlerelocs.h"
#include "elf/elfspace.h"
#include "chunk/chunk.h"
#include "chunk/concrete.h"
#include "chunk/dump.h"
#include "operation/find.h"
#include "instr/concrete.h"
#include "disasm/makesemantic.h"

#include "log/log.h"
#include "log/temp.h"

void HandleRelocsPass::visit(Module *module) {
    this->module = module;
    auto functionList = module->getFunctionList();
    for(auto r : *relocList) {
        Chunk *inner = ChunkFind().findInnermostInsideInstruction(
            functionList, r->getAddress());
        auto instruction = dynamic_cast<Instruction *>(inner);
        if(!instruction) continue;

#ifdef ARCH_X86_64
        if(!r->getSymbol()) continue;

        Function *target = CIter::findChild(functionList,
            r->getSymbol()->getName());

        if(!target) {
            if(module->getElfSpace()->getElfMap()->isObjectFile()) {
                handleRelocation(r, instruction, r->getSymbol());
            }
            continue;
        }

        // we know r is inside this module, but we don't know where yet
        LOG(10, "reloc inside " << instruction->getName() << " at "
            << r->getAddress() << " targets [" << target->getName() << "]");
#endif

        handleRelocation(r, instruction);
    }
}

void HandleRelocsPass::handleRelocation(Reloc *r, Instruction *instruction) {
    if(dynamic_cast<ControlFlowInstruction *>(instruction->getSemantic())) {
        // we don't need to do anything here because the InternalCalls pass
        // and ExternalCalls pass deal with it
        return;
    }
    if(dynamic_cast<IndirectCallInstruction *>(instruction->getSemantic())) {
        // if this is RIP-relative, we should try to convert this to
        // ControlFlowInstruction
        return;
    }
    if(dynamic_cast<IndirectJumpInstruction *>(instruction->getSemantic())) {
        return;
    }

    auto semantic = instruction->getSemantic();
    auto assembly = semantic->getAssembly();

#ifdef ARCH_X86_64
    auto linked
        = LinkedInstruction::makeLinked(module, instruction, assembly);
    if(linked) {
        instruction->setSemantic(linked);
        delete semantic;
    }
#else
    if(auto v = dynamic_cast<LiteralInstruction *>(semantic)) {
        auto linked = LinkedLiteralInstruction::makeLinked(module, instruction,
            v->getData(), r, resolveWeak);
        if(linked) {
            instruction->setSemantic(linked);
            delete semantic;
        }
    }
    else {
        auto linked = LinkedInstruction::makeLinked(module, instruction,
            assembly, r, resolveWeak);
        if(linked) {
            instruction->setSemantic(linked);
            delete semantic;
        }
    }
#endif
}

void HandleRelocsPass::handleRelocation(Reloc *r, Instruction *instruction,
    Symbol *symbol) {

#ifdef ARCH_X86_64
    if(auto v = dynamic_cast<ControlFlowInstruction *>(
        instruction->getSemantic())) {

        auto oldLink = v->getLink();

        // Symbol Only links should only be formed with relocations for object
        // files where symbol is in UND section (0)
        if(symbol->getSectionIndex() == SHN_UNDEF) {
            auto newLink = new SymbolOnlyLink(symbol, r->getAddress());
            v->setLink(newLink);
            LOG(2, " -> CREATED SYMBOL ONLY LINK");
            delete oldLink;
        }
    }
    else {
        auto semantic = instruction->getSemantic();
        auto assembly = v->getAssembly();
        auto linked = new LinkedInstruction(instruction);
        linked->setAssembly(assembly);
        instruction->setSemantic(linked);
        delete semantic;

        auto targetAddress = r->getSymbol()->getAddress() + r->getAddend();

        for(size_t op = 0;
            op < linked->getAssembly()->getAsmOperands()->getOpCount();
            op ++) {
            int opOffset = MakeSemantic::getDispOffset(&*linked->getAssembly(), op);
            if(r->getAddress() - instruction->getAddress()
                == (address_t)opOffset) {

                linked->setIndex(op);
            }
        }

        bool isRelative = MakeSemantic::isRIPRelative(
            &*linked->getAssembly(), linked->getIndex());
        auto newLink = module->getDataRegionList()->createDataLink(
            targetAddress, module, isRelative);
        linked->setLink(newLink);

        LOG(2, " -> CREATED DATA LINK");
    }
#endif
}
