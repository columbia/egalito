#include <climits>
#include <cassert>
#include <cstring>
#include <sstream>
#include "instruction.h"
#include "concrete.h"
#include "chunk.h"
#include "link.h"
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
const AARCH64_ImInfo_t AARCH64_ImInfo[AARCH64_IM_MAX] = {
      /* ADRP */
      {0x9000001F, [] (address_t dest, address_t src) {
                        diff_t disp = dest - (src & ~0xFFF);
                        uint32_t imm = disp >> 12;
                        return (((imm & 0x3) << 29) | ((imm & 0x1FFFFC) << 3));
                    }
      },
      /* BL */
      {0xFC000000, [] (address_t dest, address_t src) {
                        diff_t disp = dest - src;
                        uint32_t imm = disp >> 2;
                        return (imm & ~0xFC000000);
                    }
      },
      /* B (same as BL; but keep it separate for debugging purpose) */
      {0xFC000000, [] (address_t dest, address_t src) {
                        diff_t disp = dest - src;
                        uint32_t imm = disp >> 2;
                        return (imm & ~0xFC000000);
                    }
      },
      /* B.COND */
      {0xFF00001F, [] (address_t dest, address_t src) {
                        diff_t disp = dest - src;
                        uint32_t imm = disp >> 2;
                        return ((imm << 5)& ~0xFF00001F);
                    }
      },
};

uint32_t InstructionRebuilder::rebuild(void) {
    address_t dest = getLink()->getTargetAddress();
    uint32_t imm = imInfo->makeImm(dest, getSource()->getAddress());
#if 0
    LOG(1, "mode: " << getMode());
    LOG(1, "dest: " << dest);
    LOG(1, "fixedBytes: " << fixedBytes);
    LOG(1, "imm: " << imm);
    LOG(1, "result: " << (fixedBytes | imm));
#endif
    return fixedBytes | imm;
}

void InstructionRebuilder::writeTo(char *target) {
    *reinterpret_cast<uint32_t *>(target) = rebuild();
}
void InstructionRebuilder::writeTo(std::string &target) {
    uint32_t data = rebuild();
    target.append(reinterpret_cast<const char *>(&data), instructionSize);
}
std::string InstructionRebuilder::getData() {
    std::string data;
    writeTo(data);
    return data;
}

#endif
