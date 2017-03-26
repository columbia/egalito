#include <numeric>
#include "regreplace.h"
#include "disasm/disassemble.h"
#include "chunk/mutator.h"
#include "chunk/dump.h"
#include "log/log.h"

#ifdef ARCH_AARCH64
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

    AARCH64RegisterUsage regUsage(function, AARCH64GPRegister::R18);

    std::vector<int> count = regUsage.getAllUseCounts();
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
    FrameType *frame, AARCH64RegisterUsage *regUsage,
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

    AARCH64InstructionRegCoder coder;
    for(auto ins: regUsage->getInstructionList()) {
        auto assembly = ins->getSemantic()->getAssembly();
        if(!assembly) throw "Register replacement pass needs Assembly";

        // actually replace register(s)
        coder.decode(assembly->getBytes(), assembly->getSize());
        coder.replaceRegister(regX, dualReg);
        char data[assembly->getSize()];
        coder.encode(data, assembly->getSize());
        std::vector<unsigned char> dataVector(data, data + assembly->getSize());
        cs_insn insn = Disassemble::getInsn(dataVector, ins->getAddress());
        Assembly a(insn);
        *assembly = a;
    }
}

void AARCH64RegReplacePass::replacePerInstruction(FrameType *frame,
    AARCH64RegisterUsage *regUsage, AARCH64GPRegister::ID dualID) {

    PhysicalRegister<AARCH64GPRegister> baseReg(
        frame->getSetBPInstr() ? AARCH64GPRegister::R29 : AARCH64GPRegister::SP,
        true);
    PhysicalRegister<AARCH64GPRegister> dualReg(dualID, true);

    LOG(1, "dualID = " << dualID);

    auto bin_str0 = AARCH64InstructionBinary(0xF9000000
        | 0/8 << 10 | baseReg.encoding() << 5 | dualReg.encoding());

    auto bin_str8 = AARCH64InstructionBinary(0xF9000000
        | 8/8 << 10 | baseReg.encoding() << 5 | dualReg.encoding());

    auto bin_ldr0 = AARCH64InstructionBinary(0xF9400000
        | 0/8 << 10 | baseReg.encoding() << 5 | dualReg.encoding());

    auto bin_ldr8 = AARCH64InstructionBinary(0xF9400000
        | 8/8 << 10 | baseReg.encoding() << 5 | dualReg.encoding());

    AARCH64InstructionRegCoder coder;
    for(auto ins : regUsage->getInstructionList()) {
        auto assembly = ins->getSemantic()->getAssembly();
        if(!assembly) throw "Register replacement pass needs Assembly";
        if(assembly->getId() == ARM64_INS_BR) {
            throw "this case is not handled yet";
        }

        coder.decode(assembly->getBytes(), assembly->getSize());

        // p1. store the original value of dualReg
        auto instr_strOrg = Disassemble::instruction(bin_str0.getVector());
        ChunkMutator(ins->getParent()).insertBefore(ins, instr_strOrg);

        // p2. load the other value of dualReg (only if it will be dereferenced)
        if(coder.isReading(regX)) {
            auto instr_ldrAlt = Disassemble::instruction(bin_ldr8.getVector());
            ChunkMutator(ins->getParent()).insertBefore(ins, instr_ldrAlt);
        }

        // e2. load the original value of dualReg
        auto instr_ldrOrg = Disassemble::instruction(bin_ldr0.getVector());
        ChunkMutator(ins->getParent()).insertAfter(ins, instr_ldrOrg);

        // e1. store the other value of dualReg (only if it was written)
        if(coder.isWriting(regX)) {
            auto instr_strAlt = Disassemble::instruction(bin_str8.getVector());
            ChunkMutator(ins->getParent()).insertAfter(ins, instr_strAlt);
        }

        // actually replace register(s)
        coder.replaceRegister(regX, dualReg);
        char data[assembly->getSize()];
        coder.encode(data, assembly->getSize());
        std::vector<unsigned char> dataVector(data, data + assembly->getSize());
        cs_insn insn = Disassemble::getInsn(dataVector, ins->getAddress());
        Assembly a(insn);
        *assembly = a;
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

                if(dynamic_cast<ExternalNormalLink *>(cfi->getLink())) {
                    instructions.push_back(ins);
                }
            }
        }
    }

    return instructions;
}

void AARCH64InstructionRegCoder::decode(const char *bytes, size_t size) {
    if(size != 4) throw "non AARCH64 instruction?";
    bin = bytes[3] << 24 | bytes[2] << 16 | bytes[1] << 8 | bytes[0];
    cached = false;
}

void AARCH64InstructionRegCoder::encode(char *bytes, size_t size) {
    if(size != 4) throw "non AARCH64 instruction?";
    bytes[0] = bin >>  0 & 0xFF;
    bytes[1] = bin >>  8 & 0xFF;
    bytes[2] = bin >> 16 & 0xFF;
    bytes[3] = bin >> 24 & 0xFF;
}

bool AARCH64InstructionRegCoder::isReading(
    PhysicalRegister<AARCH64GPRegister>& reg) {

    auto list = getRegPositionList();
    for(auto rpos : list.first) {
        uint32_t rr = bin >> rpos & regMask;
        if(rr == reg.encoding()) {
            return true;
        }
    }
    return false;
}

bool AARCH64InstructionRegCoder::isWriting(
    PhysicalRegister<AARCH64GPRegister>& reg) {

    auto list = getRegPositionList();
    for(auto wpos : list.second) {
        uint32_t wr = bin >> wpos & regMask;
        if(wr == reg.encoding()) {
            return true;
        }
    }
    return false;
}


void AARCH64InstructionRegCoder::replaceRegister(
    PhysicalRegister<AARCH64GPRegister>& oldReg,
    PhysicalRegister<AARCH64GPRegister>& newReg) {

    auto list = getRegPositionList();
    for(auto rpos : list.first) {
        auto rr = bin >> rpos & regMask;
        if(rr == oldReg.encoding()) {
            bin = (bin & ~(regMask << rpos)) | (newReg.encoding() << rpos);
        }
    }

    for(auto wpos : list.second) {
        auto wr = bin >> wpos & regMask;
        if(wr == oldReg.encoding()) {
            bin = (bin & ~(regMask << wpos)) | (newReg.encoding() << wpos);
        }
    }
    cached = false;
}

AARCH64InstructionRegCoder::RegPositionsList AARCH64InstructionRegCoder::getRegPositionList() {
    if(!cached) {
        //C4.1
        auto op0 = bin >> 25 & 0xF;
        if((op0 & 0b1110) == 0b1000) makeDPImm_RegPositionList();
        else if((op0 & 0b1010) == 0b1010) makeBranch_RegPositionList();
        else if((op0 & 0b0101) == 0b0100) makeLDST_RegPositionList();
        else if((op0 & 0b0111) == 0b0101) makeDPIReg_RegPositionList();
#if 1
        else {
            throw "unhandled instruction category";
        }
#endif
        cached = true;
    }

    return list;
}

void AARCH64InstructionRegCoder::makeDPImm_RegPositionList() {
    RegPositions source;
    RegPositions destination;

    if(1
        || (bin & 0x1F000000) == 0x11000000     //C4.2.1 Add/subtract (immediate)
        || (bin & 0x1F800000) == 0x13000000     //C4.2.2 Bitfield
        || (bin & 0x1F800000) == 0x12000000     //C4.2.4 Logical (immediate)
      ) {
        source.push_back(5);
        destination.push_back(0);
    }
    else if((bin & 0x1F800000) == 0x13800000) { //C4.2.3 Extract
        source.push_back(5);
        source.push_back(16);
        destination.push_back(0);
    }
    else if(1
        || (bin & 0x1F800000) == 0x12800000     //C4.2.5 Move wide (immediate)
        || (bin & 0x1F000000) == 0x10000000     //C4.2.6 PC-rel. addressing
           ) {
        destination.push_back(0);
    }

    list = RegPositionsList(source, destination);
}

void AARCH64InstructionRegCoder::makeBranch_RegPositionList() {
    RegPositions source;
    RegPositions destination;

    if(1
        || (bin & 0xFE000000) == 0x34000000     //C4.3.1 Compare & branch (imm)
        || (bin & 0x7E000000) == 0x36000000     //C4.3.5 Test & branch (immediate)
      ) {
        source.push_back(0);
    }
    else if((bin & 0xFFC00000) == 0xD5000000    //C4.3.4 System
           ) {
        auto L = bin >> 21 & 0x1;
        auto op0 = bin >> 19 & 0x3;
        if(L == 0) {
            if(op0 == 0x1 || ((op0 & 0x3) == 0x3)) {  //SYS, MSR (register)
                source.push_back(0);
            }
        }
        else if(L == 1) { //SYSL, MRS
            destination.push_back(0);
        }
    }
    else if((bin & 0xFE000000) == 0xD6000000) { //C4.3.7 Uncoditional branch (reg)
        source.push_back(5);
    }

    //No register use
    //C4.3.2 Conditional branch (immediate)
    //C4.3.3 Exception generation
    //C4.3.6 Uncoditional branch (immediate)

    list = RegPositionsList(source, destination);
}

void AARCH64InstructionRegCoder::makeLDST_RegPositionList() {
    RegPositions source;
    RegPositions destination;

    auto op1 = bin >> 28 & 0x3;
    if(op1 == 0) {
        throw "unhandled SIMD and LD exclusive instructions";
    }

    if((bin & 0x3B000000)== 0x18000000          //C4.4.5 Load (literal)
      ) {
       destination.push_back(0);
    }
    else if(1
        || (bin & 0x3B200C00) == 0x38000400     //C4.4.8 LD/ST (imm post)
        || (bin & 0x3B200C00) == 0x38000C00     //C4.4.9 LD/ST (imm pre)
        || (bin & 0x3B200C00) == 0x38000800     //C4.4.11 LD/ST (unprivileged)
        || (bin & 0x3B200C00) == 0x38000000     //C4.4.12 LD/ST (unscaled imm)
        || (bin & 0x3B000C00) == 0x39000000     //C4.4.13 LD/ST (unsigned imm)
           ){
        auto writeback = (bin >> 10 & 0x1);
        switch((bin & 0x04000000 >> (26 - 2)) | (bin & 0x00C00000 >> 22)) {
        case 1: case 2: case 3: case 5: case 7: //LD
            source.push_back(5);
            destination.push_back(0);
            if(writeback) {
                destination.push_back(5);
            }
            break;
        case 0: case 4: case 6: //ST
            source.push_back(0);
            source.push_back(5);
            if(writeback) {
                destination.push_back(5);
            }
            break;
        default:
            break;
        }
    }
    else if((bin & 0x3B200C00) == 0x38200800) { //C4.4.10 LD/ST (register)
        switch((bin & 0x04000000 >> (26 - 2)) | (bin & 0x00C00000 >> 22)) {
        case 1: case 2: case 3: case 5: case 7: //LD
            source.push_back(5);
            source.push_back(16);
            destination.push_back(0);
        case 0: case 4: case 6: //ST
            source.push_back(0);
            source.push_back(5);
            source.push_back(16);
            break;
        default:
            break;
        }
    }
    else if(1
        || (bin & 0x3BC00000) == 0x28000000     //C4.4.7 LD/ST no-a pair (offset)
        || (bin & 0x3B800000) == 0x29000000     //C4.4.14 LD/ST pair (offset)
        || (bin & 0x3B800000) == 0x28800000     //C4.4.15 LD/ST pair (post)
        || (bin & 0x3B800000) == 0x29800000     //C4.4.15 LD/ST pair (pre)
           ) {
        auto writeback = (bin >> 23 & 0x1);
        auto L = bin >> 22 & 0x1;
        if(L) {
            source.push_back(5);
            destination.push_back(0);
            destination.push_back(10);
            if(writeback) {
                destination.push_back(5);
            }
        }
        else {
            source.push_back(0);
            source.push_back(5);
            source.push_back(10);
            if(writeback) {
                destination.push_back(5);
            }
        }
    }

    list = RegPositionsList(source, destination);
}

void AARCH64InstructionRegCoder::makeDPIReg_RegPositionList() {
    RegPositions source;
    RegPositions destination;

    if(1
        || (bin & 0x1F200000) == 0x0B200000     //C4.5.1 Add/subtract (extended)
        || (bin & 0x1F200000) == 0x0B000000     //C4.5.2 Add/subtract (shifted)
        || (bin & 0x1FE00000) == 0x1A000000     //C4.5.3 Add/subtract (w/ carry)
        || (bin & 0x1FE00800) == 0x1A400000     //C4.5.5 Conditional compare (reg)
        || (bin & 0x3FE00000) == 0x1AC00000     //C4.5.8 Data-processing (2 src)
        || (bin & 0x1F000000) == 0x0A000000     //C4.5.10 Logical (shifted)
      ) {
        source.push_back(5);
        source.push_back(16);
        destination.push_back(0);
    }
    else if(1
        || (bin & 0x1FE00800) == 0x1A400800     //C4.5.4 Conditional compare (imm)
      ) {
        source.push_back(5);
    }
    else if(1
        || (bin & 0x1FE00000) == 0x1A800000     //C4.5.6 Conditional select
      ) {
        source.push_back(5);
        source.push_back(16);
        destination.push_back(0);
    }
    else if(1
        || (bin & 0x3FE00000) == 0x3AC00000     //C4.5.7 Data-processing (1 src)
      ) {
        source.push_back(5);
        destination.push_back(0);
    }
    else if(1
        || (bin & 0x1F000000) == 0x1A000000     //C4.5.9 Data-processing (3 src)
      ) {
        source.push_back(5);
        source.push_back(10);
        source.push_back(16);
        destination.push_back(0);
    }

    list = RegPositionsList(source, destination);
}

AARCH64RegisterUsage::AARCH64RegisterUsage(Function *function,
                                           AARCH64GPRegister::ID id)
    : function(function), regX(id, true) {

    for(auto block : function->getChildren()->getIterable()->iterable()) {
        for(auto ins : block->getChildren()->getIterable()->iterable()) {
            if(auto assembly = ins->getSemantic()->getAssembly()) {
                auto asmOps = assembly->getAsmOperands();
                for(size_t i = 0; i < asmOps->getOpCount(); ++i) {
                    if(asmOps->getOperands()[i].type == ARM64_OP_REG
                       && (AARCH64GPRegister(asmOps->getOperands()[i].reg,
                                             false).id() == id)) {

                        xList.push_back(ins);
                        break;
                    }
                }
            }
        }
    }
}

std::vector<int> AARCH64RegisterUsage::getAllUseCounts() {
    int use_count[AARCH64GPRegister::REGISTER_NUMBER];
    for(size_t i = 0; i < AARCH64GPRegister::REGISTER_NUMBER; ++i) {
        use_count[i] = 0;
    }

    for(auto block : function->getChildren()->getIterable()->iterable()) {
        for(auto ins : block->getChildren()->getIterable()->iterable()) {
            if(auto assembly = ins->getSemantic()->getAssembly()) {
                auto asmOps = assembly->getAsmOperands();
                for(size_t i = 0; i < asmOps->getOpCount(); ++i) {
                    if(asmOps->getOperands()[i].type == ARM64_OP_REG) {
                        int id = PhysicalRegister<AARCH64GPRegister>(
                            asmOps->getOperands()[i].reg, false).id();

                        if(id == AARCH64GPRegister::INVALID) continue;
                        ++use_count[id];
                    }
                }
            }
            else {
                throw "RegReplacePass needs Assembly!";
            }
        }
    }
    return std::vector<int>(use_count,
                            use_count + AARCH64GPRegister::REGISTER_NUMBER);
}

std::vector<bool> AARCH64RegisterUsage::getUnusableRegister() {
    bool unusable[AARCH64GPRegister::REGISTER_NUMBER];
    for(size_t i = 0; i < AARCH64GPRegister::REGISTER_NUMBER; ++i) {
        unusable[i] = false;
    }
    for(auto ins : xList) {
        if(auto assembly = ins->getSemantic()->getAssembly()) {
            auto asmOps = assembly->getAsmOperands();
            bool withX = false;
            std::vector<int> regOperands;
            for(size_t i = 0; i < asmOps->getOpCount(); ++i) {
                if(asmOps->getOperands()[i].type == ARM64_OP_REG) {
                    int id = PhysicalRegister<AARCH64GPRegister>(
                        asmOps->getOperands()[i].reg, false).id();

                    if(id == AARCH64GPRegister::INVALID) continue;
                    if(id == regX.id()) {
                        withX = true;
                    }
                    regOperands.push_back(id);
                }

                if(withX) {
                    for(auto rid : regOperands) {
                        unusable[rid] = true;
                    }
                }
            }
        }
    }

    return std::vector<bool>(unusable,
                             unusable + AARCH64GPRegister::REGISTER_NUMBER);
}

#endif
