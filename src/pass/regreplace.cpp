#include "regreplace.h"
#include "disasm/disassemble.h"
#include "chunk/mutator.h"
#include "log/log.h"

void RegReplacePass::useStack(Function *function, FrameType *frame) {
    RegisterUsage regUsage(function, ARM64_REG_X18);

    for(auto u : regUsage.getUsage()) {
        LOG(1, "in node " << u.first->getName());
        for(auto ins : u.second) {
            LOG(1, "x18 used in instruction " << ins->getName());
        }
    }

    for(auto block : regUsage.getSingleBlockList()) {
        replaceSingle(block, frame, &regUsage);
    }

    for(auto block : regUsage.getRootBlockList()) {
        replaceRoot(block, frame, &regUsage);
    }

    for(auto block : regUsage.getLeafBlockList()) {
        replaceLeaf(block, frame, &regUsage);
    }
    ChunkMutator(function).updatePositions();
}

void RegReplacePass::replace(Block *block, FrameType *frame,
    RegisterUsage *regUsage, bool skipHead, bool skipTail) {

    Register baseReg = frame->getSetBPInstr() ? ARM64_REG_X29 : ARM64_REG_SP;
    Register dualReg = regUsage->getDualRegister(block);

    LOG(1, "dualReg for " << block->getName()
        << " is X" << (dualReg - ARM64_REG_X0));
    if(dualReg == INVALID_REGISTER) {
        throw "no register found to serve dual role";
    }

    LOG(1, "baseReg for accesing save-area is "
        << (baseReg == ARM64_REG_X29 ? "X29" : "SP"));

    auto xInstructionList = regUsage->getInstructionList(block);

    LOG(1, "skipHead : " << skipHead << " skipTail : " << skipTail);
    Instruction *begin(nullptr), *end(nullptr);
    bool inRegion;
    if(skipHead) {
        inRegion = false;
        begin = xInstructionList.front();
    }
    else {
        inRegion = true;
    }
    if(skipTail) {
        end = xInstructionList.back();
    }

    // not necessary until we do more optimization based on CFG and
    // non-presence of a jumptable
    std::vector<Instruction *> dualInstructionList;
    for(auto ins : block->getChildren()->getIterable()->iterable()) {
        if(!inRegion) {
            if(ins == begin) {
                inRegion = true;
            }
        }
        if(!inRegion) continue;

        if(ins == end) {
            //inRegion = false;
            break;
        }
        if(auto cs = ins->getSemantic()->getCapstone()) {
            cs_arm64 *x = &cs->detail->arm64;
            for(int i = 0; i < x->op_count; ++i) {
                if(x->operands[i].type == ARM64_OP_REG
                   && x->operands[i].reg == dualReg) {

                    dualInstructionList.push_back(ins);
                    break;
                }
            }
        }
    }

    for(auto ins : xInstructionList) {
        LOG(1, "regX is used in " << ins->getName());
    }
    for(auto ins : dualInstructionList) {
        LOG(1, "dualReg is used in " << ins->getName());
    }

    unsigned int baseRegEnc = baseReg == ARM64_REG_X29 ? 29 :31;
    unsigned int dualRegEnc = dualReg - ARM64_REG_X0;

    auto bin_str0 = AARCH64InstructionBinary(0xF9000000
        | 0/8 << 10 | baseRegEnc << 5 | dualRegEnc);

    auto bin_str8 = AARCH64InstructionBinary(0xF9000000
        | 8/8 << 10 | baseRegEnc << 5 | dualRegEnc);

    auto bin_ldr0 = AARCH64InstructionBinary(0xF9400000
        | 0/8 << 10 | baseRegEnc << 5 | dualRegEnc);

    auto bin_ldr8 = AARCH64InstructionBinary(0xF9400000
        | 8/8 << 10 | baseRegEnc << 5 | dualRegEnc);

    InstructionCoder coder;
    for(auto ins : xInstructionList) {
        auto cs = ins->getSemantic()->getCapstone();
        coder.decode(cs->bytes, cs->size);

        // p1. store the original value of dualReg
        auto instr_strOrg = Disassemble::instruction(bin_str0.getVector());
        ChunkMutator(block).insertBefore(ins, instr_strOrg);

        // p2. load the other value of dualReg (only if it will be dereferenced)
        if(coder.isReading(regX)) {
            auto instr_ldrAlt = Disassemble::instruction(bin_ldr8.getVector());
            ChunkMutator(block).insertBefore(ins, instr_ldrAlt);
        }

        // e2. load the original value of dualReg
        auto instr_ldrOrg = Disassemble::instruction(bin_ldr0.getVector());
        ChunkMutator(block).insertAfter(ins, instr_ldrOrg);

        // e1. store the other value of dualReg (only if it was written)
        if(coder.isWriting(regX)) {
            auto instr_strAlt = Disassemble::instruction(bin_str8.getVector());
            ChunkMutator(block).insertAfter(ins, instr_strAlt);
        }

        // actually replace register(s)
        coder.replaceRegister(regX, dualReg);
        coder.encode(cs->bytes, cs->size);
        auto s = ins->getSemantic();
        std::string raw;
        raw.assign(reinterpret_cast<char *>(cs->bytes), cs->size);
        ins->setSemantic(new RawInstruction(raw));
        delete s;
    }
}

void InstructionCoder::decode(uint8_t *bytes, size_t size) {
    if(size != 4) throw "non AARCH64 instruction?";
    bin = bytes[3] << 24 | bytes[2] << 16 | bytes[1] << 8 | bytes[0];
    cached = false;
}

void InstructionCoder::encode(uint8_t *bytes, size_t size) {
    if(size != 4) throw "non AARCH64 instruction?";
    bytes[0] = bin >>  0 & 0xFF;
    bytes[1] = bin >>  8 & 0xFF;
    bytes[2] = bin >> 16 & 0xFF;
    bytes[3] = bin >> 24 & 0xFF;
}

bool InstructionCoder::isReading(Register reg) {
    auto list = getRegPositionList();
    for(auto rpos : list.first) {
        auto rr = bin >> rpos & regMask;
        if(rr == static_cast<unsigned int>(reg - ARM64_REG_X0)) {
            return true;
        }
    }
    return false;
}

bool InstructionCoder::isWriting(Register reg) {
    auto list = getRegPositionList();
    for(auto wpos : list.second) {
        auto wr = bin >> wpos & regMask;
        if(wr == static_cast<unsigned int>(reg - ARM64_REG_X0)) {
            return true;
        }
    }
    return false;
}


void InstructionCoder::replaceRegister(Register oldName, Register newName) {
    //LOG(1, "renaming " << std::dec << (oldName - ARM64_REG_X0)
        //<< " to " << std::dec << (newName - ARM64_REG_X0));
    //LOG(1, "original bin = " << std::hex << bin);

    auto list = getRegPositionList();
    for(auto rpos : list.first) {
        auto rr = bin >> rpos & regMask;
        if(rr == static_cast<unsigned int>(oldName - ARM64_REG_X0)) {
            //LOG(1, "rpos = " << std::dec << rpos);
            bin = (bin & ~(regMask << rpos)) | ((newName - ARM64_REG_X0) << rpos);
        }
    }

    for(auto wpos : list.second) {
        auto wr = bin >> wpos & regMask;
        if(wr == static_cast<unsigned int>(oldName - ARM64_REG_X0)) {
            //LOG(1, "wpos = " << std::dec << wpos);
            bin = (bin & ~(regMask << wpos)) | ((newName - ARM64_REG_X0) << wpos);
        }
    }
    cached = false;

    //LOG(1, "new bin = " << std::hex << bin);
}

InstructionCoder::RegPositionsList InstructionCoder::getRegPositionList() {
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

void InstructionCoder::makeDPImm_RegPositionList() {
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

void InstructionCoder::makeBranch_RegPositionList() {
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

void InstructionCoder::makeLDST_RegPositionList() {
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

void InstructionCoder::makeDPIReg_RegPositionList() {
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

#if 0
void RegReplacePass::overrideRegister(cs_arm64 *x, Register dualReg) {
    for(int i = 0; i < x->op_count; ++i) {
        if(x->operands[i].reg == regX) {
            x->operands[i].reg = dualReg;
        }
    }
}
#endif
