#include "stackextend.h"
#include "chunk/chunk.h"
#include "chunk/concrete.h"
#include "chunk/instruction.h"
#include "chunk/mutator.h"
#include "disasm/disassemble.h"
#include "log/log.h"
#include "chunk/dump.h"

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
    struct frameType frame;
    memset(&frame, 0, sizeof(frame));

    if(!shouldApply(function)) return;

    auto size = getFrameSize(function);
    frame.baseSize = size;
    if(size > 0) {
        auto firstB = function->getChildren()->getIterable()->get(0);
        for(auto i : firstB->getChildren()->getIterable()->iterable()) {
            if(auto cs = i->getSemantic()->getCapstone()) {
                cs_arm64 *x = &cs->detail->arm64;
                if(x->operands[0].reg == ARM64_REG_X29
                   && x->operands[1].type == ARM64_OP_REG
                   && x->operands[1].reg == ARM64_REG_SP) {

                    if(cs->id == ARM64_INS_MOV) {
                        frame.outArgSize = 0;
                        frame.setBPInstr = i;
                    }
                    else if(cs->id == ARM64_INS_ADD) {
                        frame.outArgSize = x->operands[2].imm;
                        frame.setBPInstr = i;
                    }
                    break;
                }
            }
        }
    }

    for(auto b : function->getChildren()->getIterable()->iterable()) {
        for(auto i : b->getChildren()->getIterable()->iterable()) {
            if(dynamic_cast<ReturnInstruction *>(i->getSemantic())) {
                frame.returnInstrs.push_back(i);
            }
            else if(auto cfi = dynamic_cast<ControlFlowInstruction *>(
                i->getSemantic())) {

                if(cfi->getMnemonic() == std::string("b")
                   || cfi->getMnemonic().find("b.", 0) != std::string::npos) {

                    auto link = dynamic_cast<NormalLink *>(cfi->getLink());
                    if(link && dynamic_cast<Function *>(&*link->getTarget())) {
                        frame.returnInstrs.push_back(i);
                    }
                }
            }
        }
    }

    for(auto const &retInstr : frame.returnInstrs) {
        auto parent = dynamic_cast<Block *>(retInstr->getParent());
        for(auto i : parent->getChildren()->getIterable()->iterable()) {
            if(auto cs = i->getSemantic()->getCapstone()) {
                cs_arm64 *x = &cs->detail->arm64;
                if(cs->id == ARM64_INS_MOV
                   && x->operands[0].reg == ARM64_REG_SP
                   && x->operands[1].type == ARM64_OP_REG
                   && x->operands[1].reg == ARM64_REG_X29) {

                    frame.resetSPInstrs.push_back(i);
                }
            }
        }
    }

    CLOG(1, "frame size = 0x%x", frame.baseSize);
    CLOG(1, "out-going arg size = %d", frame.outArgSize);
    auto i = frame.setBPInstr;
    LOG(1, "BP set @ " << (i ? i->getName() : ""));

    extendStack(function, &frame);
    shrinkStack(function, &frame);

#if 0
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


size_t StackExtendPass::getFrameSize(Function *function) {
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

class AARCH64InstructionBinary {
private:
    std::vector<unsigned char> v;
public:
    AARCH64InstructionBinary(uint32_t bin)
        : v({static_cast<unsigned char>(bin >> 0  & 0xff),
             static_cast<unsigned char>(bin >> 8  & 0xff),
             static_cast<unsigned char>(bin >> 16 & 0xff),
             static_cast<unsigned char>(bin >> 24 & 0xff)}) {}
    std::vector<unsigned char> getVector() { return v; }
};

void StackExtendPass::extendStack(Function *function, struct frameType *frame) {

    auto firstB = function->getChildren()->getIterable()->get(0);
    auto bin_sub = AARCH64InstructionBinary(
        0xD1000000 | extendSize << 10 | 31 << 5 | 31);
    auto instr_sub = Disassemble::instruction(bin_sub.getVector());
    ChunkMutator(firstB).prepend(instr_sub);

    auto bin_add = AARCH64InstructionBinary(
        0x91000000 | extendSize << 10 | 29 << 5 | 29);
    auto instr_add = Disassemble::instruction(bin_add.getVector());
    if(auto ins = frame->setBPInstr) {
        auto block = dynamic_cast<Block *>(ins->getParent());
        ChunkMutator(block).insertAfter(ins, instr_add);
    }
}

void StackExtendPass::shrinkStack(Function *function, struct frameType *frame) {
    for(auto ins : frame->resetSPInstrs) {
        auto bin_sub = AARCH64InstructionBinary(
            0xD1000000 | extendSize << 10 | 29 << 5 | 29);
        auto block = dynamic_cast<Block *>(ins->getParent());
        auto instr_sub = Disassemble::instruction(bin_sub.getVector());
        ChunkMutator(block).insertBefore(ins, instr_sub);
    }

    std::map<Instruction *, Instruction *>prevs;
    for(auto ins : frame->returnInstrs) {
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
                for(auto ins : frame->returnInstrs) {
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

