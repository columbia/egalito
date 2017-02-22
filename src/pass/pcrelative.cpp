#include <capstone/capstone.h>
#include <capstone/arm64.h>
#include "chunk/instruction.h"
#include "pcrelative.h"
#include "log/log.h"

void PCRelativePass::visit(Module *module) {
    recurse(module);
}

void PCRelativePass::visit(Instruction *instruction) {
    cs_insn *cs = instruction->getSemantic()->getCapstone();
#if defined(ARCH_X86_64)
#elif defined(ARCH_AARCH64)
    cs_arm64 *x = &cs->detail->arm64;
    if(cs->id == ARM64_INS_ADRP) { //ADRP <Xd>, <label>
        cs_arm64_op *op = &x->operands[1];
        int64_t imm = op->imm;

        auto oldSemantic = instruction->getSemantic();

        auto i = new PCRelativeInstruction(instruction,
                                           cs->mnemonic,
                                           AARCH64_ADRP,
                                           cs->bytes);
        i->setLink(new DataOffsetLink(((elf->getBaseAddress() + cs->address) & ~0xfff) + imm));
        //LOG(1, "adrp target: " << i->getLink()->getTargetAddress());

        instruction->setSemantic(i);
        delete oldSemantic;
    }
    else if(cs->id == ARM64_INS_B) { //B or B.COND <label>
        cs_arm64_op *op = &x->operands[0];
        int64_t imm = op->imm;

        auto oldSemantic = instruction->getSemantic();

        CFInstructionMode m;
        if(cs->bytes[3] == 0x54) {
            m = AARCH64_BCOND;
            //LOG(1, "BCOND to: +" << imm);
        } else {
            m = AARCH64_B;
            //LOG(1, "B to: +" << imm);
        }
        auto i = new ControlFlowInstruction(instruction,
                                            cs->mnemonic,
                                            m,
                                            cs->bytes);
        //handled by resolvecalls or resolvereolcs pass if to a function
        i->setLink(new UnresolvedLink(imm));
        //LOG(1, "B or B.COND target: " << i->getLink()->getTargetAddress());

        instruction->setSemantic(i);
        delete oldSemantic;
    }
    else if(cs->id == ARM64_INS_BL) { //BL <label>
        cs_arm64_op *op = &x->operands[0];
        int64_t imm = op->imm;

        auto oldSemantic = instruction->getSemantic();

        auto i = new ControlFlowInstruction(instruction,
                                            cs->mnemonic,
                                            AARCH64_BL,
                                            cs->bytes);
        i->setLink(new UnresolvedLink(imm));

        instruction->setSemantic(i);
        delete oldSemantic;
    }

    //the subsequent 'add' must also be handled once data layout is
    //randomized
#endif
}
