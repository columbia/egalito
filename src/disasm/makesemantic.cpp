#define HAVE_DISTORM

#ifdef HAVE_DISTORM
    #include "../dep/distorm3/include/distorm.h"
#endif

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
                std::string((char *)ins->bytes, ins->size - 4),
                ins->mnemonic,
                4);
            cfi->setLink(new UnresolvedLink(imm));
            semantic = cfi;
        }
        else if(cs_insn_group(handle.raw(), ins, X86_GRP_JUMP)) {
            Assembly assembly(*ins);
            auto dispSize = determineDisplacementSize(&assembly, 0);
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
            semantic = new IndirectCallInstruction(op->reg);
            semantic->setAssembly(AssemblyPtr(new Assembly(*ins)));
        }
        else if(cs_insn_group(handle.raw(), ins, X86_GRP_JUMP)) {
            semantic = new IndirectJumpInstruction(op->reg, ins->mnemonic);
            semantic->setAssembly(AssemblyPtr(new Assembly(*ins)));
        }
    }
    else if(x->op_count > 0 && x->operands[0].type == X86_OP_MEM) {
        if(ins->id == X86_INS_CALL) {
            if((op->mem.segment == X86_REG_GS || op->mem.segment == X86_REG_FS)
                && op->mem.base == X86_REG_INVALID) {

                // just for internal libegalito.so instruction: jmpq *%gs:0x8
                semantic = new DataLinkedControlFlowInstruction(instruction);
                semantic->setLink(new UnresolvedLink(op->mem.disp));
                semantic->setAssembly(AssemblyPtr(new Assembly(*ins)));
            }
            else if(op->mem.base == X86_REG_RIP || op->mem.base == X86_REG_INVALID) {
                semantic = new DataLinkedControlFlowInstruction(instruction);
                //semantic->setLink(LinkFactory::makeDataLink(module, address, true));
                semantic->setAssembly(AssemblyPtr(new Assembly(*ins)));
            }
            else {
                semantic = new IndirectCallInstruction(
                    static_cast<Register>(op->mem.base),
                    static_cast<Register>(op->mem.index),
                    op->mem.scale, op->mem.disp);
                semantic->setAssembly(AssemblyPtr(new Assembly(*ins)));
            }
        }
        if(cs_insn_group(handle.raw(), ins, X86_GRP_JUMP)) {
            if((op->mem.segment == X86_REG_GS || op->mem.segment == X86_REG_FS)
                && op->mem.base == X86_REG_INVALID) {

                // just for internal libegalito.so instruction: jmpq *%gs:0x8
                semantic = new DataLinkedControlFlowInstruction(instruction);
                semantic->setLink(new UnresolvedLink(op->mem.disp));
                semantic->setAssembly(AssemblyPtr(new Assembly(*ins)));
            }
            else if(op->mem.base == X86_REG_RIP || op->mem.base == X86_REG_INVALID) {
                semantic = new DataLinkedControlFlowInstruction(instruction);
                //semantic->setLink(LinkFactory::makeDataLink(module, address, false));
                semantic->setAssembly(AssemblyPtr(new Assembly(*ins)));
            }
            else {
                semantic = new IndirectJumpInstruction(
                    static_cast<Register>(op->mem.base), ins->mnemonic,
                    static_cast<Register>(op->mem.index),
                    op->mem.scale, op->mem.disp);
                semantic->setAssembly(AssemblyPtr(new Assembly(*ins)));
            }
        }
    }
    else if(ins->id == X86_INS_RET) {
        semantic = new ReturnInstruction();
        semantic->setAssembly(AssemblyPtr(new Assembly(*ins)));
    }
#elif defined(ARCH_AARCH64)
    cs_arm64 *x = &ins->detail->arm64;
    cs_arm64_op *op = &x->operands[0];
    if(ins->id == ARM64_INS_BR) {
        semantic = new IndirectJumpInstruction(
            static_cast<Register>(op->reg), ins->mnemonic);
        semantic->setAssembly(AssemblyPtr(new Assembly(*ins)));
    }
    else if(ins->id == ARM64_INS_BLR) {
        semantic = new IndirectCallInstruction(static_cast<Register>(op->reg));
        semantic->setAssembly(AssemblyPtr(new Assembly(*ins)));
    }
    else if(cs_insn_group(handle.raw(), ins, ARM64_GRP_JUMP)
        || ins->id == ARM64_INS_BL) {

        auto i = new ControlFlowInstruction(instruction);
        semantic = i;
        semantic->setAssembly(AssemblyPtr(new Assembly(*ins)));
        semantic->setLink(new UnresolvedLink(i->getOriginalOffset()));
    }
    else if(ins->id == ARM64_INS_RET) {
        semantic = new ReturnInstruction();
        semantic->setAssembly(AssemblyPtr(new Assembly(*ins)));
    }
    else if(ins->id == ARM64_INS_BRK || ins->id == ARM64_INS_HLT) {
        semantic = new BreakInstruction();
        semantic->setAssembly(AssemblyPtr(new Assembly(*ins)));
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

#ifdef ARCH_RISCV
InstructionSemantic *MakeSemantic::makeNormalSemantic(
    Instruction *instruction, rv_instr *ins) {

    InstructionSemantic *semantic = nullptr;
    DisasmHandle handle(true);

    bool is_cflow = false;
    if(ins->codec == rv_codec_sb) is_cflow = true;

    const std::set<rv_op> cflow = {
        rv_op_j,
        rv_op_jr,
        rv_op_jal,
        rv_op_jalr,

        rv_op_c_j,
        rv_op_c_jr,
        rv_op_c_jal,
        rv_op_c_jalr,

        rv_op_ret
    };

    is_cflow |= cflow.count(ins->op) > 0;

    if(is_cflow) {
        auto cfi = new ControlFlowInstruction(instruction);
        semantic = cfi;

        std::string raw;
        raw.assign(reinterpret_cast<char *>(&ins->inst), ins->len);
        cfi->setData(raw);

        // for the conditional branch instructions
        // the psuedo-ops against zero have one less operand
        if(ins->op == rv_op_beqz
            || ins->op == rv_op_bnez
            || ins->op == rv_op_blez
            || ins->op == rv_op_bgez
            || ins->op == rv_op_bltz
            || ins->op == rv_op_bgtz) {

            assert(ins->oper[1].type == rv_oper::rv_oper_imm);
            cfi->setLink(new UnresolvedLink(ins->ip + ins->oper[1].value.imm));
        }
        // the rest of the conditional branches
        else if(ins->codec == rv_codec_sb) {
            assert(ins->oper[2].type == rv_oper::rv_oper_imm);
            cfi->setLink(new UnresolvedLink(ins->ip + ins->oper[2].value.imm));
        }
        else if(ins->op == rv_op_j
            || ins->op == rv_op_c_j
            || ins->op == rv_op_c_jal) {

            assert(ins->oper[0].type == rv_oper::rv_oper_imm);
            cfi->setLink(new UnresolvedLink(ins->ip + ins->oper[0].value.imm));
        }
        else if(ins->op == rv_op_jal) {
            assert(ins->oper[1].type == rv_oper::rv_oper_imm);
            cfi->setLink(new UnresolvedLink(ins->ip + ins->oper[1].value.imm));
        }
        // indirect jumps
        else if(ins->op == rv_op_jr) {
            // indirect jump to oper[0] (reg)
            delete semantic;
            assert(ins->oper[0].type == rv_oper::rv_oper_reg);
            semantic = new IndirectJumpInstruction(ins->oper[0].value.reg,
                ins->op_name);
            semantic->setAssembly(AssemblyPtr(new Assembly(*ins)));
        }
        else if(ins->op == rv_op_c_jr) {
            // indirect jump to oper[1] (reg)
            delete semantic;
            assert(ins->oper[1].type == rv_oper::rv_oper_reg);
            semantic = new IndirectJumpInstruction(ins->oper[1].value.reg,
                ins->op_name);
            semantic->setAssembly(AssemblyPtr(new Assembly(*ins)));
        }
        // indirect calls
        else if(ins->op == rv_op_jalr) {
            // oper[0] is rd
            // oper[1] is rs
            // oper[2] is imm
            // if rd is 0, it's an indirect jump
            if(ins->oper[0].value.reg == rv_ireg_zero) {
                assert(ins->oper[2].type == rv_oper::rv_oper_imm);
                assert(ins->oper[1].type == rv_oper::rv_oper_reg);
                semantic = new IndirectJumpInstruction(ins->oper[1].value.reg,
                    ins->op_name, Register::rv_reg_invalid, 0,
                    ins->oper[2].value.imm);
                semantic->setAssembly(AssemblyPtr(new Assembly(*ins)));
            }
            // otherwise it's an indirect call
            else {
                LOG(1, "JALR, destination reg is " << ins->oper[0].value.reg);
                assert(ins->oper[2].type == rv_oper::rv_oper_imm);

                assert(ins->oper[1].type == rv_oper::rv_oper_reg);
                semantic = new IndirectCallInstruction(ins->oper[1].value.reg,
                    ins->oper[2].value.imm);
                semantic->setAssembly(AssemblyPtr(new Assembly(*ins)));
            }
        }
        else if(ins->op == rv_op_c_jalr) {
            // XXX: not implemented yet
            assert(0);
        }

        else if(ins->op == rv_op_ret) {
            delete semantic;
            semantic = new ReturnInstruction();
            semantic->setAssembly(AssemblyPtr(new Assembly(*ins)));
        }

    }

    return semantic;
}
#endif

int MakeSemantic::determineDisplacementSize(Assembly *assembly, int opIndex) {
#ifdef ARCH_X86_64
#ifdef HAVE_DISTORM
    _DInst _instr[256];
    _DInst &instr = _instr[120];
    _CodeInfo ci;
    ci.code         = reinterpret_cast<const uint8_t *>(assembly->getBytes());
    ci.codeLen      = assembly->getSize();
    ci.codeOffset   = 0;  // address, don't need a real value here
    ci.dt           = Decode64Bits;
    ci.features     = DF_NONE;

    unsigned count = 0;
    if(distorm_decompose(&ci, &instr, 1, &count) != DECRES_SUCCESS
        || count != 1) {

        LOG(10, "WARNING: distorm failed");
        return 0;
    }

    if(instr.flags == FLAG_NOT_DECODABLE) return 0;

    int dispSize = -1;
    // capstone and distorm use the opposite index
    size_t i = assembly->getAsmOperands()->getOpCount() - 1 - opIndex;
    int type = instr.ops[i].type;
    if(type == O_SMEM || type == O_MEM || type == O_DISP) {
        dispSize = instr.dispSize / 8;
    }
    if(type == O_IMM || type == O_IMM1 || type == O_IMM2
        || type == O_PC || type == O_PTR) {

        dispSize = instr.ops[i].size / 8;
    }

    if(dispSize >= 0) {
        return dispSize;
    }
    else {
        //LOG(1, "WARNING: distorm does not know size of instruction displacement!");
        return 0;
    }
#else
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
#endif
#else  // not ARCH_X86_64
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
        int dispSize = determineDisplacementSize(assembly, opIndex);
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
        int dispSize = determineDisplacementSize(assembly, opIndex);
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
    LOG(10, "possible error in getDispOffset");
    return 0;
#else
    throw "getDispOffset is only meaningful on x86";
#endif
}

int MakeSemantic::getOpIndex(Assembly *assembly, size_t offset) {
#ifdef ARCH_X86_64
    for(size_t i = 0; i < assembly->getAsmOperands()->getOpCount(); i++) {
        int opOffset = MakeSemantic::getDispOffset(&*assembly, i);
        if(offset == (size_t)opOffset) {
            return i;
        }
    }
#endif
    LOG(0, "error in getOpIndex");
    return -1;
}
