#include <numeric>
#include "regreplace.h"
#include "analysis/frametype.h"
#include "analysis/reguse.h"
#include "disasm/disassemble.h"
#if defined(ARCH_AARCH64) || defined(ARCH_ARM)
    #include "disasm/aarch64-regbits.h"
#endif
#include "chunk/dump.h"
#include "operation/mutator.h"
#include "log/log.h"

#if defined(ARCH_AARCH64) || defined(ARCH_ARM)
// if we can find a register R not used within this function:
//   if R is callee saved register:
//     [CASE-1]
//     1. save R in the prologue, and restore R in the epilogue
//     2. substitute regX with R
//   else if R is a caller saved or temporary register and this is a leaf:
//     [CASE-2] -- not implemented
//     1. substitute regX with R
//     2. save and recover R before and after a call
//   endif
// else:
//   [CASE-3]
//   1. pick any callee saved register
//   2. substitute regX with R for each instruction
//   3. add extra code for the case the instruction is a branch
// endif

void AARCH64RegReplacePass::useStack(
    Function *function, FrameType *frame) {

#if 0
    ChunkDumper dumper;
    LOG(1, "original:");
    function->accept(&dumper);
#endif

    AARCH64RegisterUsageX regUsage(function, AARCH64GPRegister::R18);

    std::vector<int> count = AARCH64RegisterUsage().getAllUseCounts(function);
    std::vector<bool> unusable = regUsage.getUnusableRegister();

    AARCH64GPRegister::ID dualID;
    for(dualID = AARCH64GPRegister::R_CALLEE_SAVED_BEGIN;
        dualID <= AARCH64GPRegister::R_CALLEE_SAVED_END;
        ++dualID) {

        if(count[dualID] == 0 && !unusable[dualID]) {
            break;
        }
    }
    if(dualID <= AARCH64GPRegister::R_CALLEE_SAVED_END) {  // [CASE-1]
        LOG(1, "CASE-1 " << function->getName());
        replacePerFunction(function, frame, &regUsage, dualID);
    }
    else {  // [CASE-3]
        for(auto r = AARCH64GPRegister::R_CALLER_SAVED_BEGIN;
            r <= AARCH64GPRegister::R_CALLER_SAVED_END;
            ++r) {
            if(count[dualID] == 0 && !unusable[dualID]) {
                auto calls = getCallingInstructions(function);
                if(calls.size() < regUsage.getInstructionList().size()) {
                    // has to be sure about jump tables to implement CASE-2
                    LOG(1, "potential case for CASE-2");
                }
                break;
            }
        }

        LOG(1, "CASE-3 " << function->getName());
        for(dualID = AARCH64GPRegister::R_CALLEE_SAVED_BEGIN;
            dualID <= AARCH64GPRegister::R_CALLEE_SAVED_END;
            ++dualID) {

            if(!unusable[dualID]) {
                break;
            }
        }
        replacePerInstruction(frame, &regUsage, dualID);
    }

    ChunkMutator(function).updatePositions();

#if 0
    LOG(1, "modified:");
    function->accept(&dumper);
#endif
}

void AARCH64RegReplacePass::replacePerFunction(Function *function,
    FrameType *frame, AARCH64RegisterUsageX *regUsage,
    AARCH64GPRegister::ID dualID) {

    PhysicalRegister<AARCH64GPRegister> rSP(AARCH64GPRegister::SP, true);
    PhysicalRegister<AARCH64GPRegister> dualReg(dualID, true);

    LOG(1, "dualID = " << dualID);

    auto bin_str0 = AARCH64InstructionBinary(0xF9000000
        | 0/8 << 10 | rSP.encoding() << 5 | dualReg.encoding());
    auto bin_ldr0 = AARCH64InstructionBinary(0xF9400000
        | 0/8 << 10 | rSP.encoding() << 5 | dualReg.encoding());

    auto instr_strOrg = Disassemble::instruction(bin_str0.getVector());
    auto instr_ldrOrg = Disassemble::instruction(bin_ldr0.getVector());

    auto firstB = function->getChildren()->getIterable()->get(0);
    auto firstI = firstB->getChildren()->getIterable()->get(0);
    ChunkMutator(firstB).insertAfter(firstI, instr_strOrg);

    for(auto ins : frame->getEpilogueInstrs()) {
        ChunkMutator(ins->getParent()).insertBefore(ins, instr_ldrOrg);
        frame->fixEpilogue(ins, instr_ldrOrg);
    }

    AARCH64RegBits regbits;
    for(auto ins: regUsage->getInstructionList()) {
        auto assembly = ins->getSemantic()->getAssembly();
        if(!assembly) {
            LOG(1, "Register replacement pass needs Assembly");
            return;
        }
    }
    for(auto ins: regUsage->getInstructionList()) {
        auto assembly = ins->getSemantic()->getAssembly();
        regbits.decode(assembly->getBytes());
        regbits.replaceRegister(regX, dualReg);
        char data[assembly->getSize()];
        regbits.encode(data);
        std::vector<unsigned char> dataVector(data, data + assembly->getSize());
        *assembly = Disassemble::makeAssembly(dataVector, ins->getAddress());
    }
}

void AARCH64RegReplacePass::replacePerInstruction(FrameType *frame,
    AARCH64RegisterUsageX *regUsage, AARCH64GPRegister::ID dualID) {

    PhysicalRegister<AARCH64GPRegister> baseReg(
        frame->getSetBPInstr() ? AARCH64GPRegister::R29 : AARCH64GPRegister::SP,
        true);
    PhysicalRegister<AARCH64GPRegister> dualReg(dualID, true);

    LOG(5, "dualID = " << dualID);

    auto bin_str0 = AARCH64InstructionBinary(0xF9000000
        | 0/8 << 10 | baseReg.encoding() << 5 | dualReg.encoding());

    auto bin_str8 = AARCH64InstructionBinary(0xF9000000
        | 8/8 << 10 | baseReg.encoding() << 5 | dualReg.encoding());

    auto bin_ldr0 = AARCH64InstructionBinary(0xF9400000
        | 0/8 << 10 | baseReg.encoding() << 5 | dualReg.encoding());

    auto bin_ldr8 = AARCH64InstructionBinary(0xF9400000
        | 8/8 << 10 | baseReg.encoding() << 5 | dualReg.encoding());

    AARCH64RegBits regbits;
    for(auto ins : regUsage->getInstructionList()) {
        auto assembly = ins->getSemantic()->getAssembly();

        LOG(5, "replacing " << assembly->getMnemonic()
            << " at 0x" << std::hex << ins->getAddress());

        if(!assembly) {
            LOG(1, "Register replacement pass needs Assembly");
            continue;
        }
        if(assembly->getId() == ARM64_INS_BR) {
            throw "this case is not handled yet";
        }

        regbits.decode(assembly->getBytes());

        // p1. store the original value of dualReg
        auto instr_strOrg = Disassemble::instruction(bin_str0.getVector());
        ChunkMutator(ins->getParent()).insertBefore(ins, instr_strOrg);

        // p2. load the other value of dualReg (only if it will be dereferenced)
        if(regbits.isReading(regX)) {
            auto instr_ldrAlt = Disassemble::instruction(bin_ldr8.getVector());
            ChunkMutator(ins->getParent()).insertBefore(ins, instr_ldrAlt);
        }

        // e2. load the original value of dualReg
        auto instr_ldrOrg = Disassemble::instruction(bin_ldr0.getVector());
        ChunkMutator(ins->getParent()).insertAfter(ins, instr_ldrOrg);

        // e1. store the other value of dualReg (only if it was written)
        if(regbits.isWriting(regX)) {
            auto instr_strAlt = Disassemble::instruction(bin_str8.getVector());
            ChunkMutator(ins->getParent()).insertAfter(ins, instr_strAlt);
        }

        // actually replace register(s)
        regbits.replaceRegister(regX, dualReg);
        char data[assembly->getSize()];
        regbits.encode(data);
        std::vector<unsigned char> dataVector(data, data + assembly->getSize());
        *assembly = Disassemble::makeAssembly(dataVector, ins->getAddress());
    }
}

bool AARCH64RegReplacePass::shouldApply(Function *function) {
    for(auto b : function->getChildren()->getIterable()->iterable()) {
        for(auto i : b->getChildren()->getIterable()->iterable()) {
            if(auto assembly = i->getSemantic()->getAssembly()) {
                auto operands = assembly->getAsmOperands()->getOperands();
                if(assembly->getAsmOperands()->getOpCount() >= 1
                   && operands[0].type == ARM64_OP_REG
                   && AARCH64GPRegister(operands[0].reg, false).id() == regX.id()) {

                    LOG(1, "r18 is modified in " << function->getName()
                        << " at " << i->getName());
                    return true;
                }
            }
        }
    }

    return false;
}

std::vector<Instruction *> AARCH64RegReplacePass::getCallingInstructions(
    Function *function) {

    std::vector<Instruction *> instructions;
    for(auto block : function->getChildren()->getIterable()->iterable()) {
        for(auto ins : block->getChildren()->getIterable()->iterable()) {
            if(auto cfi = dynamic_cast<ControlFlowInstruction *>(
                ins->getSemantic())) {

                if(cfi->getLink()->isExternalLink()) {
                    instructions.push_back(ins);
                }
            }
        }
    }

    return instructions;
}

#endif
