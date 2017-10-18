#include <cstring>  // for memcmp
#include "makesemantic.h"
#include "disassemble.h"
#include "instr/assembly.h"
#include "instr/concrete.h"
#include "chunk/concrete.h"
#include "chunk/link.h"
#include "log/log.h"

InstructionSemantic *MakeSemantic::makeNormalSemantic(
    Instruction *instruction, cs_insn *ins) {

    InstructionSemantic *semantic = nullptr;
    DisasmHandle handle(true);

#if defined(ARCH_X86_64)
    cs_x86 *x = &ins->detail->x86;
    cs_x86_op *op = &x->operands[0];
    if(x->op_count > 0 && x->operands[0].type == X86_OP_IMM) {
        if(ins->id == X86_INS_CALL) {
            unsigned long imm = op->imm;
            auto cfi = new ControlFlowInstruction(
                ins->id, instruction,
                std::string((char *)ins->bytes,
                ins->size - 4),
                ins->mnemonic,
                4);
            cfi->setLink(new UnresolvedLink(imm));
            semantic = cfi;
        }
        else if(cs_insn_group(handle.raw(), ins, X86_GRP_JUMP)) {
            Assembly assembly(*ins);
            auto dispSize = determineDisplacementSize(&assembly);
            size_t use = ins->size - dispSize;
            unsigned long imm = op->imm;
            auto cfi = new ControlFlowInstruction(
                ins->id, instruction,
                std::string((char *)ins->bytes, use),
                ins->mnemonic, dispSize);
            cfi->setLink(new UnresolvedLink(imm));
            semantic = cfi;
        }
    }
    else if(x->op_count > 0 && x->operands[0].type == X86_OP_REG) {
        if(ins->id == X86_INS_CALL) {
            semantic = new IndirectCallInstruction(*ins, op->reg);
        }
        else if(cs_insn_group(handle.raw(), ins, X86_GRP_JUMP)) {
            semantic = new IndirectJumpInstruction(
                *ins, op->reg, ins->mnemonic);
        }
    }
    else if(ins->id == X86_INS_RET) {
        semantic = new ReturnInstruction(DisassembledStorage(*ins));
    }
#elif defined(ARCH_AARCH64)
    cs_arm64 *x = &ins->detail->arm64;
    cs_arm64_op *op = &x->operands[0];
    if(ins->id == ARM64_INS_BR) {
        semantic = new IndirectJumpInstruction(
            *ins, static_cast<Register>(op->reg), ins->mnemonic);
    }
    else if(ins->id == ARM64_INS_BLR) {
        semantic = new IndirectCallInstruction(
            *ins, static_cast<Register>(op->reg));
    }
    else if(cs_insn_group(handle.raw(), ins, ARM64_GRP_JUMP)
        || ins->id == ARM64_INS_BL) {

        auto i = new ControlFlowInstruction(instruction, *ins);
        i->setLink(new UnresolvedLink(i->getOriginalOffset()));
        semantic = i;
    }
    else if(ins->id == ARM64_INS_RET) {
        semantic = new ReturnInstruction(DisassembledStorage(*ins));
    }
    else if(ins->id == ARM64_INS_BRK || ins->id == ARM64_INS_HLT) {
        semantic = new BreakInstruction(DisassembledStorage(*ins));
    }
#elif defined(ARCH_ARM)
    cs_arm *x = &ins->detail->arm;
    cs_arm_op *op = &x->operands[0];

    if(cs_insn_group(handle.raw(), ins, ARM_GRP_JUMP)
        || ins->id == ARM_INS_B
        || ins->id == ARM_INS_BX
        || ins->id == ARM_INS_BL
        || ins->id == ARM_INS_BLX
        || ins->id == ARM_INS_BXJ
        || ins->id == ARM_INS_CBZ
        || ins->id == ARM_INS_CBNZ) {

        if(x->op_count > 0 && op->type == ARM_OP_IMM) {
            auto i = new ControlFlowInstruction(instruction, *ins);
            i->setLink(new UnresolvedLink(i->getOriginalOffset()));
            semantic = i;
        }
        else if(x->op_count > 0 && op->type == ARM_OP_REG) {
            // bx lr or b lr are return instructions
            if(std::strcmp(cs_reg_name(handle.raw(), op->reg), "lr") == 0)  {
                semantic = new ReturnInstruction(DisassembledStorage(*ins));
            }
            else {
                semantic = new IndirectJumpInstruction(
                    *ins, static_cast<Register>(op->reg), ins->mnemonic);
            }
        }
    }
    else if(ins->id == ARM_INS_POP) {
        // if pc in pop instruction then considered a return instruction.
        for(int i = 0; i < x->op_count; i++) {
            if(std::strcmp(cs_reg_name(handle.raw(), (&x->operands[i])->reg),
                "pc") == 0) {

                semantic = new ReturnInstruction(DisassembledStorage(*ins));
                break;
            }
        }
    }
#endif

    return semantic;
}

int MakeSemantic::determineDisplacementSize(Assembly *assembly) {
#ifdef ARCH_X86_64
    switch(assembly->getSize()) {
    case 2: return 1;
    case 3: return 1;
    case 4: return 1;
    case 5: return 4;
    case 6: return 4;
    case 7: return 4;
    case 8: return 4;  // call *%gs:0xf00
    case 9: return 4;  // never actually observed
    case 10: return 4;
    case 11: return 4;
    default: return 0;
    }
#else
    return 0;
#endif
}

bool MakeSemantic::isRIPRelative(Assembly *assembly, int opIndex) {
#ifdef ARCH_X86_64
    auto op = &assembly->getAsmOperands()->getOperands()[opIndex];
    return (op->type == X86_OP_MEM
        && op->mem.base == X86_REG_RIP
        && op->mem.index == X86_REG_INVALID
        && op->mem.scale == 1);
#else
    return false;
#endif
}

int MakeSemantic::getDispOffset(Assembly *assembly, int opIndex) {
#ifdef ARCH_X86_64
    auto op = &assembly->getAsmOperands()->getOperands()[opIndex];
    if(op->type == X86_OP_MEM) {
        int dispSize = determineDisplacementSize(assembly);
        int offset = assembly->getSize() - dispSize;

        while(offset > 0) {
            unsigned long disp = op->mem.disp;
            // !!! this probably only works for 32-bit displacements
            if(std::memcmp(reinterpret_cast<const void *>(
                assembly->getBytes() + offset), &disp, dispSize) == 0) {

                break;
            }
            offset --;
        }
        return offset;
    }
    else if(op->type == X86_OP_IMM) {
        int dispSize = determineDisplacementSize(assembly);
        int offset = assembly->getSize() - dispSize;

        while(offset > 0) {
            unsigned long disp = op->imm;
            // !!! this probably only works for 32-bit displacements
            if(std::memcmp(reinterpret_cast<const void *>(
                assembly->getBytes() + offset), &disp, dispSize) == 0) {

                break;
            }
            offset --;
        }
        return offset;
    }
    LOG(0, "error");
    return 0;
#else
    throw "getDispOffset is only meaningful on x86";
#endif
}
