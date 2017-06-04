#include "assembly.h"
#include "instr/register.h"
#include "log/log.h"

#ifdef ARCH_AARCH64
void AssemblyOperands::overrideCapstone(const cs_insn &insn) {
    // capstone decodes the second operands to be of type register
    //  ldr x1, [x1] -> reg, reg
    //  ldr x2, [x2, #3584] -> reg, mem
    // though the first case is just the special case of the second case
    if(insn.id == ARM64_INS_LDR) {
        if(insn.detail->arm64.op_count == 2
           && insn.detail->arm64.operands[1].type == ARM64_OP_REG) {
            operands[1].type = ARM64_OP_MEM;
            operands[1].mem.base = insn.detail->arm64.operands[1].reg;
            operands[1].mem.index = INVALID_REGISTER;
            operands[1].mem.disp = 0;
            LOG(100, "overriding @ 0x" << std::hex << insn.address);
        }
    }
}
#endif

AssemblyOperands::OperandsMode AssemblyOperands::getMode() const {
    OperandsMode mode = MODE_UNKNOWN;
#ifdef ARCH_X86_64
    if(op_count == 2
        && operands[0].type == X86_OP_REG
        && operands[1].type == X86_OP_REG) {

        mode = MODE_REG_REG;
    }
    if(op_count == 2
        && operands[0].type == X86_OP_MEM
        && operands[1].type == X86_OP_REG) {

        mode = MODE_MEM_REG;
    }
    if(op_count == 2
        && operands[0].type == X86_OP_IMM
        && operands[1].type == X86_OP_REG) {

        mode = MODE_IMM_REG;
    }
#elif defined(ARCH_AARCH64)
    if(op_count == 2) {
        if(operands[0].type == ARM64_OP_REG
            && operands[1].type == ARM64_OP_REG) {

            mode = MODE_REG_REG;
        }
        else if(operands[0].type == ARM64_OP_REG
            && operands[1].type == ARM64_OP_IMM) {

            mode = MODE_REG_IMM;
        }
        else if(operands[0].type == ARM64_OP_REG
            && operands[1].type == ARM64_OP_MEM) {

            mode = MODE_REG_MEM;
        }
    }
    else if(op_count == 3) {
        if(operands[0].type == ARM64_OP_REG
            && operands[1].type == ARM64_OP_REG
            && operands[2].type == ARM64_OP_REG) {

            mode = MODE_REG_REG_REG;
        }
        else if(operands[0].type == ARM64_OP_REG
            && operands[1].type == ARM64_OP_REG
            && operands[2].type == ARM64_OP_IMM) {

            mode = MODE_REG_REG_IMM;
        }
        else if(operands[0].type == ARM64_OP_REG
            && operands[1].type == ARM64_OP_REG
            && operands[2].type == ARM64_OP_MEM) {

            mode = MODE_REG_REG_MEM;
        }
    }
#elif defined(ARCH_ARM)
    mode = MODE_UNKNOWN;
#endif
    return mode;
}
