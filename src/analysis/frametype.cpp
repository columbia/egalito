#include <capstone/capstone.h>
#include "frametype.h"
#include "analysis/jumptable.h"
#include "chunk/chunk.h"
#include "chunk/concrete.h"
#include "instr/instr.h"
#include "instr/concrete.h"
#include "instr/semantic.h"
#ifdef ARCH_X86_64
#include "instr/linked-x86_64.h"
#endif
#ifdef ARCH_AARCH64
#include "instr/linked-aarch64.h"
#endif
#include "log/log.h"
#include "log/temp.h"

FrameType::FrameType(Function *function) : setBPInstr(nullptr) {
    this->hasFrame = detectFrame(function);
    if(hasFrame) {
        auto firstB = function->getChildren()->getIterable()->get(0);
        for(auto ins : firstB->getChildren()->getIterable()->iterable()) {
            if(auto assembly = ins->getSemantic()->getAssembly()) {
                auto asmOps = assembly->getAsmOperands();
#ifdef ARCH_X86_64
                if(assembly->getId() == X86_INS_MOV
                    && assembly->getAsmOperands()->getOpCount() == 2
                    && asmOps->getOperands()[0].type == X86_OP_REG
                    && asmOps->getOperands()[0].reg == X86_REG_RSP
                    && asmOps->getOperands()[1].type == X86_OP_REG
                    && asmOps->getOperands()[1].reg ==  X86_REG_RBP) {

                    setBPInstr = ins;
                    break;
                }
#elif defined(ARCH_AARCH64)
                if(asmOps->getOpCount() >= 2
                    && asmOps->getOperands()[0].type == ARM64_OP_REG
                    && asmOps->getOperands()[0].reg == ARM64_REG_X29
                    && asmOps->getOperands()[1].type == ARM64_OP_REG
                    && asmOps->getOperands()[1].reg == ARM64_REG_SP) {

                    if(assembly->getId() == ARM64_INS_MOV) {
                        setBPInstr = ins;
                    }
                    else if(assembly->getId() == ARM64_INS_ADD) {
                        setBPInstr = ins;
                    }
                    break;
                }
#endif
            }
        }
    }

    auto module = dynamic_cast<Module *>(function->getParent()->getParent());
    for(auto b : function->getChildren()->getIterable()->iterable()) {
        for(auto ins : b->getChildren()->getIterable()->iterable()) {
            if(dynamic_cast<ReturnInstruction *>(ins->getSemantic())) {
                epilogueInstrs.push_back(ins);
            }
            else if(auto cfi = dynamic_cast<ControlFlowInstruction *>(
                ins->getSemantic())) {

#ifdef ARCH_X86_64
                if(cfi->getMnemonic() == "callq") continue;
#elif defined(ARCH_AARCH64)
                if(cfi->getAssembly()->getId() == ARM64_INS_BL) continue;
#endif
                if(auto link = dynamic_cast<NormalLink *>(cfi->getLink())) {
                    if(auto f = dynamic_cast<Function *>(&*link->getTarget())) {
                        if(f != function) epilogueInstrs.push_back(ins);
                    }
                    continue;
                }
                if(dynamic_cast<PLTLink *>(cfi->getLink())) {
                    epilogueInstrs.push_back(ins);
                    continue;
                }
            }
            else if(dynamic_cast<IndirectJumpInstruction *>(
                ins->getSemantic())) {

                bool tablejump = false;
                for(auto jt : CIter::children(module->getJumpTableList())) {
                    if(ins == jt->getDescriptor()->getInstruction()) {
                        tablejump = true;
                        break;
                    }
                }
                if(!tablejump) epilogueInstrs.push_back(ins);
            }
        }
    }

    for(auto const &retInstr : epilogueInstrs) {
        auto parent = dynamic_cast<Block *>(retInstr->getParent());
        for(auto ins : parent->getChildren()->getIterable()->iterable()) {
            if(auto assembly = ins->getSemantic()->getAssembly()) {
                auto operands = assembly->getAsmOperands()->getOperands();
#ifdef ARCH_X86_64
                if(assembly->getId() == X86_INS_ADD
                    && assembly->getAsmOperands()->getOpCount() == 2
                    && operands[0].type == X86_OP_IMM
                    && operands[1].type == X86_OP_REG
                    && operands[1].reg == X86_REG_RSP) {

                    resetSPInstrs.push_back(ins);
                }
#elif defined(ARCH_AARCH64)
                if(assembly->getId() == ARM64_INS_MOV
                    && operands[0].reg == ARM64_REG_SP
                    && operands[1].type == ARM64_OP_REG
                    && operands[1].reg == ARM64_REG_X29) {

                    resetSPInstrs.push_back(ins);
                }
#endif
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

bool FrameType::detectFrame(Function *function) {
#ifdef ARCH_X86_64
    for(auto block : CIter::children(function)) {
        for(auto ins : CIter::children(block)) {
            if(auto assembly = ins->getSemantic()->getAssembly()) {
                auto operands = assembly->getAsmOperands()->getOperands();
                if(assembly->getId() == X86_INS_PUSH) {
                    return true;
                }
                if(assembly->getId() == X86_INS_SUB
                    && assembly->getAsmOperands()->getOpCount() == 2
                    && operands[0].type == X86_OP_IMM
                    && operands[1].type == X86_OP_REG
                    && operands[1].reg == X86_REG_RSP) {

                    return true;
                }
            }
        }
    }
    return false;
#elif defined(ARCH_AARCH64)
    auto firstB = function->getChildren()->getIterable()->get(0);
    for(auto ins : firstB->getChildren()->getIterable()->iterable()) {
        if(auto assembly = ins->getSemantic()->getAssembly()) {
            auto operands = assembly->getAsmOperands()->getOperands();
            auto writeback = assembly->getAsmOperands()->getWriteback();
            if(assembly->getId() == ARM64_INS_SUB
                && operands[0].reg == ARM64_REG_SP) {

                return true;
            }
            else if(assembly->getId() == ARM64_INS_STP
                && operands[2].type == ARM64_OP_MEM
                && writeback) {

                return true;
            }
        }
    }
    return false;
#endif
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
    LOG(1, "BP set at " << (setBPInstr ? setBPInstr->getName() : ""));
    for(auto i : resetSPInstrs) {
        LOG(1, "SP reset at " << std::hex << i->getAddress());
    }
    for(auto i : epilogueInstrs) {
        LOG(1, "function epilogue starts at " << std::hex << i->getAddress());
    }
}

