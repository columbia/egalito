#include "relocheck.h"
#include "chunk/chunk.h"
#include "chunk/concrete.h"
#include "instr/concrete.h"
#include "operation/find.h"
#include "log/log.h"

void ReloCheckPass::visit(Module *module) {
#if defined(ARCH_AARCH64) || defined(ARCH_ARM)
    for(auto r : *relocList) {
        if(0
            || (r->getType() == R_AARCH64_LD_PREL_LO19)         // ld(literal)
            || (r->getType() == R_AARCH64_ADR_PREL_LO21)        // adr -- not yet implemented
            || (r->getType() == R_AARCH64_ADR_PREL_PG_HI21)     // adrp
            || (r->getType() == R_AARCH64_ADR_PREL_PG_HI21_NC)  // adrp
            || (r->getType() == R_AARCH64_ADR_GOT_PAGE)         // adrp for GOT
            || (r->getType() == R_AARCH64_JUMP26)               // (usually) tail call
            || (r->getType() == R_AARCH64_CALL26)               // bl

            || (r->getType() == R_AARCH64_ABS64)                // function pointer data

            || (r->getType() == R_AARCH64_ADD_ABS_LO12_NC)      // pointers to data
            || (r->getType() == R_AARCH64_LDST8_ABS_LO12_NC)
            || (r->getType() == R_AARCH64_LDST16_ABS_LO12_NC)
            || (r->getType() == R_AARCH64_LDST32_ABS_LO12_NC)
            || (r->getType() == R_AARCH64_LDST64_ABS_LO12_NC)
            || (r->getType() == R_AARCH64_LD64_GOT_LO12_NC)
           ) {
            if(module->getName() == "module-(executable)")
            checkSemantic(r, module->getFunctionList());
        }
        else {
            if (1
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
    }
#endif
}

void ReloCheckPass::checkSemantic(Reloc *r, FunctionList *list) {
    Chunk *inner = ChunkFind().findInnermostInsideInstruction(list, r->getAddress());
    if(auto i = dynamic_cast<Instruction *>(inner)) {
        if(auto v = dynamic_cast<LinkedInstruction *>(i->getSemantic())) {
            LOG0(10, "relocation at " << std::hex << r->getAddress());
            if(dynamic_cast<UnresolvedLink *>(v->getLink())) {
                LOG(1, " NOT resolved! addend " << r->getAddend());
            }
            else {
                LOG(10, " resolved to " << v->getLink()->getTarget()->getName()
                    << " (" << v->getLink()->getTargetAddress() << ")");
            }
        }
        else {
            LOG(0, i->getName() << " is still a normal DisassembledInstruction :(");
        }
    }
    else {
        //LOG(1, "address (0x" << r->getAddress() << ") points to a local symbol or data");
    }
}
