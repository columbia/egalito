#include <algorithm>
#include <string>
#include "stackextend.h"
#include "chunk/chunk.h"
#include "chunk/concrete.h"
#include "chunk/instruction.h"
#include "chunk/mutator.h"
#include "chunk/register.h"
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

#if 1
    LOG(1, "modified:");
    ChunkDumper dumper;
    function->accept(&dumper);
#endif
}

bool StackExtendPass::shouldApply(Function *function) {
    for(auto b : function->getChildren()->getIterable()->iterable()) {
        for(auto i : b->getChildren()->getIterable()->iterable()) {
            if(auto cs = i->getSemantic()->getCapstone()) {
                cs_arm64 *x = &cs->detail->arm64;
                if(x->op_count >= 1
                   && x->operands[0].type == ARM64_OP_REG
                   && (x->operands[0].reg == ARM64_REG_X18
                       || x->operands[0].reg == ARM64_REG_W18)) {

                    LOG(1, "x18 is modified in " << function->getName()
                        << " at " << i->getName());

                    LOG(1, "original:");
                    ChunkDumper dumper;
                    function->accept(&dumper);
                    return true;
                }
            }
        }
    }

    return false;
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

    std::map<Instruction *, Instruction *>prevs;
    for(auto ins : frame->getReturnInstrs()) {
        auto bin_add = AARCH64InstructionBinary(
            0x91000000 | extendSize << 10 | 31 << 5 | 31);
        auto block = dynamic_cast<Block *>(ins->getParent());
        auto instr_add = Disassemble::instruction(bin_add.getVector());
        ChunkMutator(block).insertBefore(ins, instr_add);
        prevs[ins] = instr_add;
    }

    for(auto b : function->getChildren()->getIterable()->iterable()) {
        for(auto i : b->getChildren()->getIterable()->iterable()) {
            if(auto cfi = dynamic_cast<ControlFlowInstruction *>(
                i->getSemantic())) {

                auto link = cfi->getLink();
                for(auto ins : frame->getReturnInstrs()) {
                    if(link->getTarget() == ins) {
                        cfi->setLink(new NormalLink(prevs[ins]));
                        delete link;
                        break;
                    }
                }
            }
        }
    }
}

FrameType::FrameType(Function *function)
    : baseSize(0), outArgSize(0), setBPInstr(nullptr) {
    baseSize = getFrameSize(function);

    if(baseSize > 0) {
        auto firstB = function->getChildren()->getIterable()->get(0);
        for(auto i : firstB->getChildren()->getIterable()->iterable()) {
            if(auto cs = i->getSemantic()->getCapstone()) {
                cs_arm64 *x = &cs->detail->arm64;
                if(x->operands[0].type == ARM64_OP_REG
                   && x->operands[0].reg == ARM64_REG_X29
                   && x->operands[1].type == ARM64_OP_REG
                   && x->operands[1].reg == ARM64_REG_SP) {

                    if(cs->id == ARM64_INS_MOV) {
                        outArgSize = 0;
                        setBPInstr = i;
                    }
                    else if(cs->id == ARM64_INS_ADD) {
                        outArgSize = x->operands[2].imm;
                        setBPInstr = i;
                    }
                    break;
                }
            }
        }
    }

    for(auto b : function->getChildren()->getIterable()->iterable()) {
        for(auto i : b->getChildren()->getIterable()->iterable()) {
            if(dynamic_cast<ReturnInstruction *>(i->getSemantic())) {
                returnInstrs.push_back(i);
            }
            else if(auto cfi = dynamic_cast<ControlFlowInstruction *>(
                i->getSemantic())) {

                if(cfi->getMnemonic() == std::string("b")
                   || cfi->getMnemonic().find("b.", 0) != std::string::npos) {

                    auto link = dynamic_cast<NormalLink *>(cfi->getLink());
                    if(link && dynamic_cast<Function *>(&*link->getTarget())) {
                        returnInstrs.push_back(i);
                    }
                }
            }
        }
    }

    for(auto const &retInstr : returnInstrs) {
        auto parent = dynamic_cast<Block *>(retInstr->getParent());
        for(auto i : parent->getChildren()->getIterable()->iterable()) {
            if(auto cs = i->getSemantic()->getCapstone()) {
                cs_arm64 *x = &cs->detail->arm64;
                if(cs->id == ARM64_INS_MOV
                   && x->operands[0].reg == ARM64_REG_SP
                   && x->operands[1].type == ARM64_OP_REG
                   && x->operands[1].reg == ARM64_REG_X29) {

                    resetSPInstrs.push_back(i);
                }
            }
        }
    }
}

size_t FrameType::getFrameSize(Function *function) {
    auto firstB = function->getChildren()->getIterable()->get(0);
    for(auto i : firstB->getChildren()->getIterable()->iterable()) {
        if(auto cs = i->getSemantic()->getCapstone()) {
            cs_arm64 *x = &cs->detail->arm64;
            if(cs->id == ARM64_INS_SUB
               && x->operands[0].reg == ARM64_REG_SP) {
                return x->operands[2].imm;  // doesn't handle shift and ext
            }
            else if(cs->id == ARM64_INS_STP
                    && x->operands[2].type == ARM64_OP_MEM
                    && x->writeback) {
                return -(x->operands[2].mem.disp);
            }
        }
    }
    return 0;
}

void FrameType::dump() {
    CLOG(1, "frame size = 0x%x", baseSize);
    CLOG(1, "out-going arg size = %d", outArgSize);
    LOG(1, "BP set @ " << (setBPInstr ? setBPInstr->getName() : ""));
}

#endif

