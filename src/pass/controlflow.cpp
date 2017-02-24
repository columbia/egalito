#include <capstone/capstone.h>
#include <capstone/arm64.h>
#include "chunk/instruction.h"
#include "controlflow.h"
#include "log/log.h"

void ControlFlowPass::visit(Module *module) {
    recurse(module);
}

void ControlFlowPass::visit(Instruction *instruction) {
    cs_insn *cs = instruction->getSemantic()->getCapstone();
#if defined(ARCH_X86_64)
#elif defined(ARCH_AARCH64)
    cs_arm64 *x = &cs->detail->arm64;
    if(cs->id == ARM64_INS_B) { //B or B.COND <label>
        cs_arm64_op *op = &x->operands[0];
        int64_t imm = op->imm;

        auto oldSemantic = instruction->getSemantic();

        InstructionMode m;
        if(cs->bytes[3] == 0x54) {
            m = AARCH64_IM_BCOND;
            //LOG(1, "BCOND to: +" << imm);
        } else {
            m = AARCH64_IM_B;
            //LOG(1, "B to: +" << imm);
        }
        auto i = new ControlFlowInstruction(instruction,
                                            cs->mnemonic,
                                            m,
                                            cs->bytes);
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
                                            AARCH64_IM_BL,
                                            cs->bytes);
        i->setLink(new UnresolvedLink(imm));

        instruction->setSemantic(i);
        delete oldSemantic;
    }
#endif
}
