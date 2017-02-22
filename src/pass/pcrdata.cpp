#include <capstone/capstone.h>
#include <capstone/arm64.h>
#include "chunk/instruction.h"
#include "pcrdata.h"
#include "log/log.h"

void PCRDataPass::visit(Module *module) {
    recurse(module);
}

void PCRDataPass::visit(Instruction *instruction) {
    cs_insn *cs = instruction->getSemantic()->getCapstone();
#if defined(ARCH_X86_64)
#elif defined(ARCH_AARCH64)
    if(!cs) {
        //ControlFlowInstruction
        //LOG(1, "no cs: " << instruction->getName());
        return;
    }
    if(cs->id == ARM64_INS_ADRP) { //ADRP <Xd>, <label>
        cs_arm64 *x = &cs->detail->arm64;
        cs_arm64_op *op = &x->operands[1];
        int64_t imm = op->imm;

        auto i = new PCRelativeInstruction(instruction,
                                           cs->mnemonic,
                                           AARCH64_Enc_ADRP,
                                           cs->bytes);
        i->setLink(new DataOffsetLink((cs->address & ~0xfff) + imm));

        instruction->setSemantic(i);
    }
    //the subsequent 'add' must also be handled once data layout is
    //randomized
#endif
}
