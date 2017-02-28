#include "makesemantic.h"
#include "disassemble.h"
#include "chunk/concrete.h"
#include "chunk/link.h"

#if defined(ARCH_X86_64)
    #define PLAT_(x) X86_ ## x
#else
    #define PLAT_(x) ARM64_ ## x
#endif

InstructionSemantic *MakeSemantic::makeNormalSemantic(
    Instruction *instruction, cs_insn *ins) {

    InstructionSemantic *semantic = nullptr;
    Disassemble::Handle handle(true);

#if defined(ARCH_X86_64)
    cs_x86 *x = &ins->detail->x86;
    cs_x86_op *op = &x->operands[0];
    if(x->op_count > 0 && x->operands[0].type == X86_OP_IMM) {
        if(ins->id == X86_INS_CALL) {
            unsigned long imm = op->imm;
            auto cfi = new ControlFlowInstruction(instruction,
                std::string((char *)ins->bytes,
                ins->size - 4),
                ins->mnemonic,
                4);
            cfi->setLink(new UnresolvedLink(imm));
            semantic = cfi;
        }
        else if(cs_insn_group(handle.raw(), ins, X86_GRP_JUMP)) {
            size_t use = ins->size /* - op->size*/;
            unsigned long imm = op->imm;
            auto cfi = new ControlFlowInstruction(instruction,
                std::string((char *)ins->bytes, use),
                ins->mnemonic,
                /*op->size*/ 0);
            cfi->setLink(new UnresolvedLink(imm));
            semantic = cfi;
        }
    }
    else if(x->op_count > 0 && x->operands[0].type == X86_OP_REG) {
        if(cs_insn_group(handle.raw(), ins, X86_GRP_JUMP)) {
            semantic = new IndirectJumpInstruction(
                *ins, op->reg, ins->mnemonic);
        }
    }
#elif defined(ARCH_AARCH64)
    cs_arm64 *x = &ins->detail->arm64;
    cs_arm64_op *op = &x->operands[0];
    if(ins->id == ARM64_INS_B || ins->id == ARM64_INS_BL) {
        auto i = new ControlFlowInstruction(instruction, *ins);
        i->setLink(new UnresolvedLink(i->getOriginalOffset()));
        semantic = i;
    }
    else if(ins->id == ARM64_INS_BR) {
        semantic = new IndirectJumpInstruction(
                *ins, static_cast<Register>(op->reg), ins->mnemonic);
    }
#endif
    else if(ins->id == PLAT_(INS_RET)) {
        semantic = new ReturnInstruction(*ins);
    }

    return semantic;
}
