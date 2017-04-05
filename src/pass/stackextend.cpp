#include <algorithm>
#include <string>
#include "stackextend.h"
#include "chunk/chunk.h"
#include "chunk/concrete.h"
#include "chunk/mutator.h"
#include "instr/concrete.h"
#include "disasm/disassemble.h"
#include "log/log.h"
#include "chunk/dump.h"

#ifdef ARCH_AARCH64
void StackExtendPass::visit(Module *module) {
    if(extendSize >= 4096) {
        LOG(1, "can't extend over 4096");
    }
    else {
        LOG(1, "extending by " << extendSize);
        recurse(module);
    }
}

void StackExtendPass::visit(Function *function) {
    if(!shouldApply(function)) return;

    FrameType frame(function);
    frame.dump();

    addExtendStack(function, &frame);
    addShrinkStack(function, &frame);
    ChunkMutator(function).updatePositions();
    useStack(function, &frame);

#if 0
    LOG(1, "modified:");
    ChunkDumper dumper;
    function->accept(&dumper);
#endif
}

void StackExtendPass::addExtendStack(Function *function, FrameType *frame) {

    auto firstB = function->getChildren()->getIterable()->get(0);
    auto bin_sub = AARCH64InstructionBinary(
        0xD1000000 | extendSize << 10 | 31 << 5 | 31);
    auto instr_sub = Disassemble::instruction(bin_sub.getVector());
    ChunkMutator(firstB).prepend(instr_sub);

    auto bin_add = AARCH64InstructionBinary(
        0x91000000 | extendSize << 10 | 29 << 5 | 29);
    auto instr_add = Disassemble::instruction(bin_add.getVector());
    if(auto ins = frame->getSetBPInstr()) {
        auto block = dynamic_cast<Block *>(ins->getParent());
        ChunkMutator(block).insertAfter(ins, instr_add);
        frame->setSetBPInstr(instr_add);
    }
}

void StackExtendPass::addShrinkStack(Function *function, FrameType *frame) {
    for(auto ins : frame->getResetSPInstrs()) {
        auto bin_sub = AARCH64InstructionBinary(
            0xD1000000 | extendSize << 10 | 29 << 5 | 29);
        auto block = dynamic_cast<Block *>(ins->getParent());
        auto instr_sub = Disassemble::instruction(bin_sub.getVector());
        ChunkMutator(block).insertBefore(ins, instr_sub);
    }

    for(auto ins : frame->getEpilogueInstrs()) {
        auto bin_add = AARCH64InstructionBinary(
            0x91000000 | extendSize << 10 | 31 << 5 | 31);
        auto block = dynamic_cast<Block *>(ins->getParent());
        auto instr_add = Disassemble::instruction(bin_add.getVector());
        ChunkMutator(block).insertBefore(ins, instr_add);
        frame->fixEpilogue(ins, instr_add);
    }
}

FrameType::FrameType(Function *function)
    : baseSize(0), outArgSize(0), setBPInstr(nullptr) {
    baseSize = getFrameSize(function);

    if(baseSize > 0) {
        auto firstB = function->getChildren()->getIterable()->get(0);
        for(auto ins : firstB->getChildren()->getIterable()->iterable()) {
            if(auto assembly = ins->getSemantic()->getAssembly()) {
                auto asmOps = assembly->getAsmOperands();
                if(asmOps->getOpCount() >= 2
                   && asmOps->getOperands()[0].type == ARM64_OP_REG
                   && asmOps->getOperands()[0].reg == ARM64_REG_X29
                   && asmOps->getOperands()[1].type == ARM64_OP_REG
                   && asmOps->getOperands()[1].reg == ARM64_REG_SP) {

                    if(assembly->getId() == ARM64_INS_MOV) {
                        outArgSize = 0;
                        setBPInstr = ins;
                    }
                    else if(assembly->getId() == ARM64_INS_ADD) {
                        outArgSize = asmOps->getOperands()[2].imm;
                        setBPInstr = ins;
                    }
                    break;
                }
            }
        }
    }

    for(auto b : function->getChildren()->getIterable()->iterable()) {
        for(auto ins : b->getChildren()->getIterable()->iterable()) {
            if(dynamic_cast<ReturnInstruction *>(ins->getSemantic())) {
                epilogueInstrs.push_back(ins);
            }
            else if(auto cfi = dynamic_cast<ControlFlowInstruction *>(
                ins->getSemantic())) {

                if(cfi->getMnemonic() == std::string("b")
                   || cfi->getMnemonic().find("b.", 0) != std::string::npos) {

                    auto link = dynamic_cast<NormalLink *>(cfi->getLink());
                    if(link && dynamic_cast<Function *>(&*link->getTarget())) {
                        epilogueInstrs.push_back(ins);
                    }
                }
            }
        }
    }

    for(auto const &retInstr : epilogueInstrs) {
        auto parent = dynamic_cast<Block *>(retInstr->getParent());
        for(auto ins : parent->getChildren()->getIterable()->iterable()) {
            if(auto assembly = ins->getSemantic()->getAssembly()) {
                auto operands = assembly->getAsmOperands()->getOperands();
                if(assembly->getId() == ARM64_INS_MOV
                   && operands[0].reg == ARM64_REG_SP
                   && operands[1].type == ARM64_OP_REG
                   && operands[1].reg == ARM64_REG_X29) {

                    resetSPInstrs.push_back(ins);
                }
            }
        }
    }

    for(auto block : function->getChildren()->getIterable()->iterable()) {
        for(auto ins : block->getChildren()->getIterable()->iterable()) {
            if(auto cfi = dynamic_cast<ControlFlowInstruction *>(
                ins->getSemantic())) {

                for(auto ins : epilogueInstrs) {
                    if(cfi->getLink()->getTarget() == ins) {
                        jumpToEpilogueInstrs.push_back(cfi);
                        break;
                    }
                }
            }
        }
    }
}

size_t FrameType::getFrameSize(Function *function) {
    auto firstB = function->getChildren()->getIterable()->get(0);
    for(auto ins : firstB->getChildren()->getIterable()->iterable()) {
        if(auto assembly = ins->getSemantic()->getAssembly()) {
            auto operands = assembly->getAsmOperands()->getOperands();
            auto writeback = assembly->getAsmOperands()->getWriteback();
            if(assembly->getId() == ARM64_INS_SUB
               && operands[0].reg == ARM64_REG_SP) {
                return operands[2].imm;  // doesn't handle shift and ext
            }
            else if(assembly->getId() == ARM64_INS_STP
                    && operands[2].type == ARM64_OP_MEM
                    && writeback) {
                return -(operands[2].mem.disp);
            }
        }
    }
    return 0;
}

void FrameType::fixEpilogue(Instruction *oldInstr, Instruction *newInstr) {
    for(auto &ins : epilogueInstrs) {
        if(ins == oldInstr) {
            *&ins = newInstr;
            break;
        }
    }

    for(auto cfi : jumpToEpilogueInstrs) {
        auto link = cfi->getLink();
        if(link->getTarget() == oldInstr) {
            cfi->setLink(new NormalLink(newInstr));
            delete link;
        }
    }
}

void FrameType::dump() {
    CLOG(1, "frame size = 0x%x", baseSize);
    CLOG(1, "out-going arg size = %d", outArgSize);
    LOG(1, "BP set @ " << (setBPInstr ? setBPInstr->getName() : ""));
}

#endif

