#include <climits>
#include <cassert>
#include <cstring>
#include <sstream>
#include "instruction.h"
#include "concrete.h"
#include "chunk.h"
#include "link.h"
#include "disasm/disassemble.h"
#include "disasm/makesemantic.h"  // for determineDisplacementSize
#include "log/log.h"

void RawByteStorage::writeTo(char *target) {
    std::memcpy(target, rawData.c_str(), rawData.size());
}
void RawByteStorage::writeTo(std::string &target) {
    target.append(rawData);
}
std::string RawByteStorage::getData() {
    return rawData;
}

DisassembledStorage::DisassembledStorage(const cs_insn &insn) {
    this->insn = insn;
    if(insn.detail) {
        // Make a copy of capstone's internal data. This breaks the library
        // abstraction a little bit. We assume nothing else is dynamically
        // allocated within a cs_insn.
        detail = new cs_detail(*insn.detail);
        this->insn.detail = detail;
    }
    else detail = nullptr;
}

DisassembledStorage::DisassembledStorage(DisassembledStorage &&other) {
    this->insn = other.insn;
    this->detail = other.detail;
    other.detail = nullptr;
}

DisassembledStorage::~DisassembledStorage() {
    delete detail;
}

DisassembledStorage &DisassembledStorage::operator = (
    DisassembledStorage &&other) {

    delete detail;
    this->insn = other.insn;
    this->detail = other.detail;
    other.detail = nullptr;
    return *this;
}

void DisassembledStorage::writeTo(char *target) {
    std::memcpy(target, insn.bytes, insn.size);
}
void DisassembledStorage::writeTo(std::string &target) {
    target.append(reinterpret_cast<const char *>(insn.bytes), insn.size);
}
std::string DisassembledStorage::getData() {
    std::string data;
    data.assign(reinterpret_cast<const char *>(insn.bytes), insn.size);
    return std::move(data);
}

#ifdef ARCH_X86_64
void ControlFlowInstruction::setSize(size_t value) {
    diff_t disp = value - opcode.size();
    assert(disp >= 0);
    assert(disp == 1 || disp == 2 || disp == 4);

    displacementSize = disp;
}

void ControlFlowInstruction::writeTo(char *target) {
    std::memcpy(target, opcode.c_str(), opcode.size());
    diff_t disp = calculateDisplacement();
    std::memcpy(target + opcode.size(), &disp, displacementSize);
}
void ControlFlowInstruction::writeTo(std::string &target) {
    target.append(opcode);
    diff_t disp = calculateDisplacement();
    target.append(reinterpret_cast<const char *>(&disp), displacementSize);
}
std::string ControlFlowInstruction::getData() {
    std::string data;
    writeTo(data);
    return data;
}

diff_t ControlFlowInstruction::calculateDisplacement() {
    address_t dest = getLink()->getTargetAddress();
    diff_t disp = dest - (getSource()->getAddress() + getSize());

#if 0  // this does not work
    unsigned long mask = (1 << (displacementSize * CHAR_BIT)) - 1;
    bool fits = false;
    if(disp >= 0) {
        if(disp == (disp & mask)) fits = true;
    }
    else {
        if((-disp) == ((-disp) & mask)) fits = true;
    }
    if(!fits) {
        std::ostringstream stream;
        stream << "writing ControlFlowInstruction with disp size "
            << displacementSize << ", but value " << disp
            << " is too large to encode";
        LOG(0, stream.str());
        throw stream.str();
    }
#endif

    return disp;
}

#elif defined(ARCH_AARCH64)
InstructionRebuilder::InstructionRebuilder(Instruction *source, Mode mode,
    const cs_insn &insn)
    : source(source), mnemonic(insn.mnemonic), modeInfo(&AARCH64_ImInfo[mode]) {

    std::memcpy(&fixedBytes, insn.bytes, 4);
    fixedBytes &= modeInfo->fixedMask;

    cs_arm64 *x = &insn.detail->arm64;
    if(x->operands[modeInfo->immediateIndex].type == ARM64_OP_IMM) {
        originalOffset = x->operands[modeInfo->immediateIndex].imm;
    }
    else {  // mem for LDR x0, [x0,#4048]
        originalOffset = x->operands[modeInfo->immediateIndex].mem.disp;
    }
}

const InstructionRebuilder::AARCH64_modeInfo_t InstructionRebuilder::AARCH64_ImInfo[AARCH64_IM_MAX] = {

      /* ADRP */
      {0x9000001F,
       [] (address_t dest, address_t src) {
           diff_t disp = dest - (src & ~0xFFF);
           uint32_t imm = disp >> 12;
           return (((imm & 0x3) << 29) | ((imm & 0x1FFFFC) << 3)); },
       1},
      /* ADDIMM (in combination with ADRP) */
      {0xFFC003FF,
       [] (address_t dest, address_t src) {
           diff_t disp = dest & 0xFFF;
           uint32_t imm = disp << 10;
           return (imm & ~0xFFC003FF); },
       2
      },
      /* LDR (immediate: unsigned offset) */
      {0xFFE003FF,
       [] (address_t dest, address_t src) {
           diff_t disp = dest - src;
           uint32_t imm = (disp >> 3) << 10;
           return (imm & ~0xFFE003FF); },
       1
      },
      /* BL <label> */
      {0xFC000000,
       [] (address_t dest, address_t src) {
           diff_t disp = dest - src;
           uint32_t imm = disp >> 2;
           return (imm & ~0xFC000000); },
       0
      },
      /* B <label> (same as BL; keep it separate for debugging purpose) */
      {0xFC000000,
       [] (address_t dest, address_t src) {
           diff_t disp = dest - src;
           uint32_t imm = disp >> 2;
           return (imm & ~0xFC000000); },
       0
      },
      /* B.COND <label> */
      {0xFF00001F,
       [] (address_t dest, address_t src) {
           diff_t disp = dest - src;
           uint32_t imm = disp >> 2;
           return ((imm << 5)& ~0xFF00001F); },
       0
      },

      /* CBZ <Xt>, <label> */
      {0xFF00001F,
       [] (address_t dest, address_t src) {
           diff_t disp = dest - src;
           uint32_t imm = disp >> 2;
           return ((imm << 5)& ~0xFF00001F); },
       1
      },
      /* CBNZ <Xt>, <label> */
      {0xFF00001F,
       [] (address_t dest, address_t src) {
           diff_t disp = dest - src;
           uint32_t imm = disp >> 2;
           return ((imm << 5)& ~0xFF00001F); },
       1
      },
      /* TBZ <Xt>, #<imm>, <label> */
      {0xFFF8001F,
       [] (address_t dest, address_t src) {
           diff_t disp = dest - src;
           uint32_t imm = disp >> 2;
           return ((imm << 5)& ~0xFFF8001F); },
       2
      },
      /* TBNZ <Xt>, #<imm>, <label> */
      {0xFFF8001F,
       [] (address_t dest, address_t src) {
           diff_t disp = dest - src;
           uint32_t imm = disp >> 2;
           return ((imm << 5)& ~0xFFF8001F); },
       2
      },
};

uint32_t InstructionRebuilder::rebuild(void) {
    address_t dest = getLink()->getTargetAddress();
    uint32_t imm = getModeInfo()->makeImm(dest, getSource()->getAddress());
#if 0
    LOG(1, "mode: " << getModeInfo() - AARCH64_ImInfo);
    LOG(1, "src: " << getSource()->getAddress());
    LOG(1, "dest: " << dest);
    LOG(1, "fixedBytes: " << getFixedBytes());
    LOG(1, "imm: " << imm);
    LOG(1, "result: " << (getFixedBytes() | imm));
#endif
    return getFixedBytes() | imm;
}

void InstructionRebuilder::writeTo(char *target) {
    *reinterpret_cast<uint32_t *>(target) = rebuild();
}
void InstructionRebuilder::writeTo(std::string &target) {
    uint32_t data = rebuild();
    target.append(reinterpret_cast<const char *>(&data), getSize());
}
std::string InstructionRebuilder::getData() {
    std::string data;
    writeTo(data);
    return data;
}

InstructionRebuilder::Mode ControlFlowInstruction::getMode(const cs_insn &insn) {
    InstructionRebuilder::Mode m;
    if(insn.id == ARM64_INS_B) {
        if(insn.bytes[3] == 0x54) {
            m = AARCH64_IM_BCOND;
        }
        else {
            m = AARCH64_IM_B;
        }
    }
    else if(insn.id == ARM64_INS_BL) {
        m = AARCH64_IM_BL;
    }
    else if(insn.id == ARM64_INS_CBZ) {
        m = AARCH64_IM_CBZ;
    }
    else if(insn.id == ARM64_INS_CBNZ) {
        m = AARCH64_IM_CBNZ;
    }
    else if(insn.id == ARM64_INS_TBZ) {
        m = AARCH64_IM_TBZ;
    }
    else if(insn.id == ARM64_INS_TBNZ) {
        m = AARCH64_IM_TBNZ;
    }
    else {
        std::cerr << "mnemonic: " << insn.mnemonic << "\n";
        throw "ControlFlowInstruction: not yet implemented";
    }
    return m;
}

InstructionRebuilder::Mode PCRelativeInstruction::getMode(const cs_insn &insn) {
    InstructionRebuilder::Mode m;
    if(insn.id == ARM64_INS_ADRP) {
        m = AARCH64_IM_ADRP;
    }
    else if(insn.id == ARM64_INS_ADD) {
        m = AARCH64_IM_ADDIMM;
    }
    else if(insn.id == ARM64_INS_LDR) {
        m = AARCH64_IM_LDR;
    }
    else {
        throw "PCRelativeInstruction: not yet implemented";
    }
    return m;
}

cs_insn InstructionRebuilder::generateCapstone() {
    auto data = AARCH64InstructionBinary(rebuild());
    return Disassemble::getInsn(data.getVector(), getSource()->getAddress());
}

#endif

int LinkedInstruction::getDispSize() {
    return MakeSemantic::determineDisplacementSize(getCapstone());
}

unsigned LinkedInstruction::calculateDisplacement() {
    unsigned int newDisp = getLink()->getTargetAddress()
        - (instruction->getAddress() + getSize());
    return newDisp;
}

void LinkedInstruction::writeTo(char *target) {
    cs_insn *insn = getCapstone();
    auto dispSize = getDispSize();
    unsigned int newDisp = calculateDisplacement();
    int dispOffset = MakeSemantic::getDispOffset(insn, opIndex);
    int i = 0;
    std::memcpy(target + i, insn->bytes + i, dispOffset);
    i += dispOffset;
    std::memcpy(target + i, &newDisp, dispSize);
    i += dispSize;
    std::memcpy(target + i, insn->bytes + i,
        insn->size - dispSize - dispOffset);
}

void LinkedInstruction::writeTo(std::string &target) {
    cs_insn *insn = getCapstone();
    auto dispSize = getDispSize();
    unsigned int newDisp = calculateDisplacement();
    int dispOffset = MakeSemantic::getDispOffset(insn, opIndex);
    target.append(reinterpret_cast<const char *>(insn->bytes),
        dispOffset);
    target.append(reinterpret_cast<const char *>(&newDisp), dispSize);
    target.append(reinterpret_cast<const char *>(insn->bytes)
        + dispOffset + dispSize,
        insn->size - dispSize - dispOffset);
}

std::string LinkedInstruction::getData() {
    std::string data;
    writeTo(data);
    return std::move(data);
}

void LinkedInstruction::regenerateCapstone() {
    // Recreate the internal capstone data structure.
    // Useful for printing the instruction (ChunkDumper).
    std::string data = getData();
    std::vector<unsigned char> dataVector;
    for(size_t i = 0; i < data.length(); i ++) {
        dataVector.push_back(data[i]);
    }
    cs_insn ins = Disassemble::getInsn(dataVector, instruction->getAddress());
    DisassembledStorage storage(ins);
    setStorage(std::move(storage));
}

unsigned AbsoluteLinkedInstruction::calculateDisplacement() {
    return getLink()->getTargetAddress();
}
