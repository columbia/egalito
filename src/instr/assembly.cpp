#include <sstream>

#include "assembly.h"
#include "disasm/dump.h"
#include "instr/register.h"
#include "log/log.h"


#ifdef ARCH_RISCV
Assembly::Assembly(const rv_instr &instr) : operands(instr) {
    id = instr.op;
    for(uint8_t i = 0; i < instr.len; i++) {
        bytes.push_back((instr.inst >> (i * 8)) & 0xff);
    }
    mnemonic = instr.op_name;

    regs_read_count = 0;

    // instructions with no register writes
    if(instr.codec == rv_codec_sb
        || instr.codec == rv_codec_r_f
        || instr.codec == rv_codec_none
        || instr.codec == rv_codec_illegal
        || instr.codec == rv_codec_ci_none
        || instr.codec == rv_codec_s
        || instr.codec == rv_codec_cs_sw
        || instr.codec == rv_codec_cs_sd
        || instr.codec == rv_codec_css_swsp
        || instr.codec == rv_codec_css_sdsp
        || instr.codec == rv_codec_cb
        || instr.codec == rv_codec_sb
        || mnemonic == "sfence.vm"
        || mnemonic == "sfence.vma"
        || mnemonic == "j"
        ) {

        regs_write_count = 0;
    }
    else {
        // one single reg write
        regs_write_count = 1;
        assert(instr.oper[0].type == rv_oper::rv_oper_reg);
        regs_write.push_back(instr.oper[0].value.reg);
    }

    for(size_t i = regs_write_count; i < instr.oper_count; i ++) {
        switch(instr.oper[i].type) {
            case rv_oper::rv_oper_imm: break;
            case rv_oper::rv_oper_reg:
                regs_read.push_back(instr.oper[i].value.reg);
                break;
            case rv_oper::rv_oper_mem:
                regs_read.push_back(instr.oper[i].value.mem.basereg);
                break;
            default:
                break;
        }
    }
    regs_read_count = regs_read.size();

    // build operandString
    std::ostringstream ss;
    for(size_t i = 0; i < instr.oper_count; i ++) {
        if(i != 0) ss << ", ";
        switch(instr.oper[i].type) {
            case rv_oper::rv_oper_imm:
                ss << std::hex << "0x" << instr.oper[i].value.imm;
                break;
            case rv_oper::rv_oper_reg:
                ss << std::dec <<
                    DisasmDump::getRegisterName(instr.oper[i].value.reg);
                break;
            case rv_oper::rv_oper_mem:
                ss << std::hex << "0x" << instr.oper[i].value.mem.disp << "("
                    << DisasmDump::getRegisterName(
                        instr.oper[i].value.mem.basereg) << ")";
                break;
            default:
                break;
        }
    }
    operandString = ss.str();
}
#endif

#ifdef ARCH_X86_64
void AssemblyOperands::overrideCapstone(const cs_insn &insn) {
    if(insn.id == X86_INS_CMP) {
        // capstone in egalitoci
        if(insn.detail->x86.op_count > 2) {
            op_count = 2;
            operands[0] = operands[1];
            operands[1] = operands[2];
        }
    }
}
#endif

#ifdef ARCH_AARCH64
void AssemblyOperands::overrideCapstone(const cs_insn &insn) {
    if(insn.id == ARM64_INS_LDR
        || insn.id == ARM64_INS_LDRB
        || insn.id == ARM64_INS_LDRH
        || insn.id == ARM64_INS_LDRSB
        || insn.id == ARM64_INS_LDRSH
        || insn.id == ARM64_INS_LDRSW
        || insn.id == ARM64_INS_STR
        || insn.id == ARM64_INS_STRB
        || insn.id == ARM64_INS_STRH) {

        // capstone decodes the second operands to be of type register
        //  ldr x1, [x1] -> reg, reg
        //  ldr x2, [x2, #3584] -> reg, mem
        // though the first case is just the special case of the second case
        if(insn.detail->arm64.op_count == 2
            && insn.detail->arm64.operands[1].type == ARM64_OP_REG) {

            operands[1].type = ARM64_OP_MEM;
            operands[1].mem.base = insn.detail->arm64.operands[1].reg;
            operands[1].mem.index = INVALID_REGISTER;
            operands[1].mem.disp = 0;
            LOG(100, "overriding @ 0x" << std::hex << insn.address);
        }

        //  ldr x1, [x2, x3] is decoded as reg, reg, reg
        //  we change it to reg, mem
        if(insn.detail->arm64.op_count == 3
            && insn.detail->arm64.operands[1].type == ARM64_OP_REG
            && insn.detail->arm64.operands[2].type == ARM64_OP_REG) {

            op_count = 2;
            operands[1].type = ARM64_OP_MEM;
            operands[1].mem.base = insn.detail->arm64.operands[1].reg;
            operands[1].mem.index = insn.detail->arm64.operands[2].reg;
            operands[1].mem.disp = 0;
            LOG(100, "overriding @ 0x" << std::hex << insn.address);
        }
    }
    else if(insn.id == ARM64_INS_LDP
        || insn.id == ARM64_INS_STP) {

        // same for load/store pair variants
        if(insn.detail->arm64.op_count == 3
            && insn.detail->arm64.operands[2].type == ARM64_OP_REG) {

            operands[2].type = ARM64_OP_MEM;
            operands[2].mem.base = insn.detail->arm64.operands[2].reg;
            operands[2].mem.index = INVALID_REGISTER;
            operands[2].mem.disp = 0;
            LOG(100, "overriding @ 0x" << std::hex << insn.address);
        }
    }
}

bool Assembly::isPostIndex() const {
    uint32_t bin = bytes[3] << 24 | bytes[2] << 16 | bytes[1] << 8 | bytes[0];
    if(id == ARM64_INS_LDP || id == ARM64_INS_STP) {
        return (bin & 0x3B800000) == 0x28800000;
    }
    else if(id == ARM64_INS_LDR || id == ARM64_INS_STR) {
        return (bin & 0x3B200C00) == 0x38000400;
    }
    return false;
}
bool Assembly::isPreIndex() const {
    uint32_t bin = bytes[3] << 24 | bytes[2] << 16 | bytes[1] << 8 | bytes[0];
    if(id == ARM64_INS_LDP || id == ARM64_INS_STP) {
        return (bin & 0x3B800000) == 0x29800000;
    }
    else if(id == ARM64_INS_LDR || id == ARM64_INS_STR) {
        return (bin & 0x3B200C00) == 0x38000C00;
    }
    return false;
}
#endif

void Assembly::overrideCapstone(const cs_insn &insn) {
#ifdef ARCH_AARCH64
    if(insn.id == ARM64_INS_MOVZ) {
        // MOV is preferred when the value is in [0, 0xFFFF].
        if(insn.detail->arm64.operands[1].type == ARM64_OP_IMM
            && insn.detail->arm64.operands[1].imm < (0x1LL<<16)) {

            id = ARM64_INS_MOV;
            mnemonic = "mov";
        }
    }
#endif
}


AssemblyOperands::OperandsMode AssemblyOperands::getMode() const {
    OperandsMode mode = MODE_UNKNOWN;
#ifdef ARCH_X86_64
    if(op_count == 1
        && operands[0].type == X86_OP_REG) {

        mode = MODE_REG;
    }
    if(op_count == 1
        && operands[0].type == X86_OP_IMM) {

        mode = MODE_IMM;
    }
    if(op_count == 1
        && operands[0].type == X86_OP_MEM) {

        mode = MODE_MEM;
    }
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
    if(op_count == 2
        && operands[0].type == X86_OP_IMM
        && operands[1].type == X86_OP_MEM) {

        mode = MODE_IMM_MEM;
    }
    if(op_count == 2
        && operands[0].type == X86_OP_REG
        && operands[1].type == X86_OP_MEM) {

        mode = MODE_REG_MEM;
    }
#elif defined(ARCH_AARCH64)
    if(op_count == 0) {
        mode = MODE_NONE;
    }
    else if(op_count == 1) {
        if(operands[0].type == ARM64_OP_REG) {
            mode = MODE_REG;
        }
        else if(operands[0].type == ARM64_OP_IMM) {
            mode = MODE_IMM;
        }
    }
    else if(op_count == 2) {
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
        else if(operands[0].type == ARM64_OP_REG
            && operands[1].type == ARM64_OP_MEM
            && operands[2].type == ARM64_OP_IMM) {

            mode = MODE_REG_MEM_IMM;
        }
    }
    else if(op_count == 4) {
        if(operands[0].type == ARM64_OP_REG
            && operands[1].type == ARM64_OP_REG
            && operands[2].type == ARM64_OP_REG
            && operands[3].type == ARM64_OP_REG) {

            mode = MODE_REG_REG_REG_REG;
        }
        else if(operands[0].type == ARM64_OP_REG
            && operands[1].type == ARM64_OP_REG
            && operands[2].type == ARM64_OP_MEM
            && operands[3].type == ARM64_OP_IMM) {

            mode = MODE_REG_REG_MEM_IMM;
        }
        else if(operands[0].type == ARM64_OP_REG
            && operands[1].type == ARM64_OP_REG
            && operands[2].type == ARM64_OP_IMM
            && operands[3].type == ARM64_OP_IMM) {

            mode = MODE_REG_REG_IMM_IMM;
        }
    }
    else {
        LOG(1, "op_count = " << int(op_count));
    }
#elif defined(ARCH_ARM)
    mode = MODE_UNKNOWN;
#endif
    return mode;
}
