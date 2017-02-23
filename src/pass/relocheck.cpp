#include "relocheck.h"
#include "chunk/chunk.h"
#include "chunk/concrete.h"
#include "chunk/instruction.h"
#include "chunk/find.h"
#include "log/log.h"

void ReloCheckPass::visit(Module *module) {
    for(auto r : *relocList) {
#ifdef ARCH_AARCH64
        if(0
           || (r->getType() == R_AARCH64_LD_PREL_LO19)          //ld(literal)
           || (r->getType() == R_AARCH64_ADR_PREL_LO21)         //adr -- not yet implemented
           || (r->getType() == R_AARCH64_ADR_PREL_PG_HI21)      //adrp
           || (r->getType() == R_AARCH64_ADR_PREL_PG_HI21_NC)   //adrp
           || (r->getType() == R_AARCH64_ADR_GOT_PAGE)          //adrp for GOT
           || (r->getType() == R_AARCH64_JUMP26)                //(usually) tail call
           || (r->getType() == R_AARCH64_CALL26)                //bl
           ) {
            checkSemantic(r, module);
        }
        else {
            if (1
                //function pointers -- needs to be handled
                && (r->getType() != R_AARCH64_ABS64)

                //should be same unless data (inc. GOT) moves
                && (r->getType() != R_AARCH64_ADD_ABS_LO12_NC)
                && (r->getType() != R_AARCH64_LDST8_ABS_LO12_NC)
                && (r->getType() != R_AARCH64_LDST64_ABS_LO12_NC)
                && (r->getType() != R_AARCH64_LD64_GOT_LO12_NC)

                //related to GOT & PLT
                && (r->getType() != R_AARCH64_GLOB_DAT)
                && (r->getType() != R_AARCH64_JUMP_SLOT)
                && (r->getType() != R_AARCH64_RELATIVE)

                //seems to be only used in .eh_frame
                && (r->getType() != R_AARCH64_PREL32)
               ) {
                LOG(1, "unhandled reloc type " << std::dec << r->getType()
                    << " at 0x" << std::hex << r->getAddress());
            }
        }
#endif
    }
}

void ReloCheckPass::checkSemantic(Reloc *r, Module *module) {
    Chunk *inner = ChunkFind().findInnermostInsideInstruction(module, r->getAddress());
    if(auto i = dynamic_cast<Instruction *>(inner)) {
        if(dynamic_cast<DisassembledInstruction *>(i->getSemantic())) {
            LOG(1, i->getName() << "is still a normal DisassembledInstruction :(");
        }
    }
}
