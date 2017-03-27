#include <elf.h>
#include <capstone/arm64.h>
#include "pcrelative.h"
#include "chunk/chunk.h"
#include "chunk/concrete.h"
#include "chunk/instruction.h"
#include "chunk/find.h"
#include "log/log.h"

void PCRelativePass::visit(Module *module) {
#if defined(ARCH_X86_64)
#elif defined(ARCH_AARCH64)
    auto functionList = module->getFunctionList();
    for(auto r : *relocList) {
        auto t = r->getType();
        if ((t == R_AARCH64_ADR_GOT_PAGE)
            || (t == R_AARCH64_ADR_PREL_PG_HI21)
            || (t == R_AARCH64_ADR_PREL_PG_HI21_NC)
            /* || (t == R_AARCH64_ADR_PREL_LO21) */
            /* || (t == R_AARCH64_LD64_GOT_LO12_NC) */
            ) {
            handlePCRelative(r, functionList);
        }
    }
#endif
}

void PCRelativePass::handlePCRelative(Reloc *r, FunctionList *functionList) {
#if defined(ARCH_X86_64)
#elif defined(ARCH_AARCH64)
    Chunk *inner = ChunkFind().findInnermostInsideInstruction(functionList,
                                                              r->getAddress());
    if(auto i = dynamic_cast<Instruction *>(inner)) {
        if(auto v = dynamic_cast<DisassembledInstruction *>(i->getSemantic())) {
            // dynamic_cast<> can't tell if it's DisassembledInstruction or
            // RelocationInstruction
            if(v->getLink()) return;

            auto pcri = new PCRelativeInstruction(i, *v->getAssembly());
            address_t offset = pcri->getOriginalOffset();

            // note: this won't work unless PCRelativeInstruction has a LinkDecorator
            pcri->setLink(new DataOffsetLink(elf, offset));
            //auto assembly = v->getAssembly();
            //LOG(1, assembly->getMnemonic() << "@" << std::hex << i->getAddress());
            //LOG(1, " target: " << std::hex << pcri->getLink()->getTargetAddress());

            i->setSemantic(pcri);
            delete v;
        }
    }
#endif
}

