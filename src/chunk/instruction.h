#ifndef EGALITO_CHUNK_INSTRUCTION_H
#define EGALITO_CHUNK_INSTRUCTION_H

#include <cstring>
#include <string>
#include <capstone/capstone.h>  // for cs_insn
#include "types.h"

class Instruction;
class Link;

/** Abstract base class for special instruction data.
*/
class InstructionSemantic {
public:
    virtual ~InstructionSemantic() {}

    virtual size_t getSize() const = 0;
    virtual void setSize(size_t value) = 0;

    virtual Link *getLink() const = 0;
    virtual void setLink(Link *newLink) = 0;

    virtual void writeTo(char *target) = 0;
    virtual void writeTo(std::string &target) = 0;
    virtual std::string getData() = 0;

    virtual cs_insn *getCapstone() = 0;
};

#if 0
class Storage {
public:
    virtual ~Storage() {}

    virtual size_t getSize() const = 0;

    virtual void writeTo(char *target) = 0;
    virtual void writeTo(std::string &target) = 0;
    virtual std::string getData() const = 0;
};

class RawByteStorage : public Storage {
private:
    std::string rawData;
public:
    RawByteStorage(const std::string &rawData) : rawData(rawData) {}

    virtual size_t getSize() const { return rawData.size(); }

    virtual void writeTo(char *target);
    virtual void writeTo(std::string &target);
    virtual std::string getData() const;
};

class DisassembledStorage : public Storage {
private:
    cs_insn insn;
public:
    DisassembledStorage(const cs_insn &insn) : insn(insn) {}

    virtual size_t getSize() const { return insn.size; }

    virtual void writeTo(char *target);
    virtual void writeTo(std::string &target);
    virtual std::string getData() const;
};
#else
class RawByteStorage {
private:
    std::string rawData;
public:
    RawByteStorage(const std::string &rawData) : rawData(rawData) {}

    size_t getSize() const { return rawData.size(); }

    void writeTo(char *target);
    void writeTo(std::string &target);
    std::string getData();

    cs_insn *getCapstone() { return nullptr; }
};

class DisassembledStorage {
private:
    cs_insn insn;
public:
    DisassembledStorage(const cs_insn &insn) : insn(insn) {}

    size_t getSize() const { return insn.size; }

    void writeTo(char *target);
    void writeTo(std::string &target);
    std::string getData();

    cs_insn *getCapstone() { return &insn; }
};
#endif

template <typename Storage>
class SemanticImpl : public InstructionSemantic {
private:
    Storage storage;
public:
    SemanticImpl(const Storage &storage) : storage(storage) {}

    Storage &getStorage() { return storage; }

    virtual size_t getSize() const { return storage.getSize(); }
    virtual void setSize(size_t value)
        { throw "Can't set size for this instruction type!"; }

    virtual Link *getLink() const { return nullptr; }
    virtual void setLink(Link *newLink)
        { throw "Can't set link for this instruction type!"; }

    virtual void writeTo(char *target) { storage.writeTo(target); }
    virtual void writeTo(std::string &target) { storage.writeTo(target); }
    virtual std::string getData() { return storage.getData(); }

    virtual cs_insn *getCapstone() { return storage.getCapstone(); }
};

template <typename BaseType>
class LinkDecorator : public BaseType {
private:
    Link *link;
public:
    LinkDecorator() : link(nullptr) {}

    template <typename Storage>
    LinkDecorator(const Storage &storage) : BaseType(storage) {}

    virtual Link *getLink() const { return link; }
    virtual void setLink(Link *link) { this->link = link; }
};

// --- concrete classes follow ---

typedef SemanticImpl<RawByteStorage> RawInstruction;
typedef SemanticImpl<DisassembledStorage> DisassembledInstruction;
typedef LinkDecorator<SemanticImpl<DisassembledStorage>> RelocationInstruction;

#ifdef ARCH_X86_64
class ControlFlowInstruction : public LinkDecorator<InstructionSemantic> {
private:
    Instruction *source;
    std::string opcode;
    std::string mnemonic;
    int displacementSize;
public:
    ControlFlowInstruction(Instruction *source, std::string opcode, std::string mnemonic, int displacementSize)
        : source(source), opcode(opcode), mnemonic(mnemonic), displacementSize(displacementSize) {}

    virtual size_t getSize() const { return opcode.size() + displacementSize; }
    virtual void setSize(size_t value);

    virtual void writeTo(char *target);
    virtual void writeTo(std::string &target);
    virtual std::string getData();

    virtual cs_insn *getCapstone() { return nullptr; }

    Instruction *getSource() const { return source; }
    std::string getMnemonic() const { return mnemonic; }
private:
    diff_t calculateDisplacement();
};
typedef LinkDecorator<SemanticImpl<DisassembledStorage>> PCRelativeInstruction;
#elif defined(ARCH_AARCH64)
class ControlFlowInstruction : public LinkDecorator<InstructionSemantic> {
private:
    Instruction *source;
    std::string mnemonic;
    const uint32_t displacementMask = ~(0xFC000000u);
    const uint32_t opcode = 0x94000000u;
    const size_t instructionSize = 4;
public:
    ControlFlowInstruction(Instruction *source, std::string mnemonic)
        : source(source), mnemonic(mnemonic) {}

    virtual size_t getSize() const { return instructionSize; }
    virtual void setSize(size_t value)
        { throw "Size is constant for AARCH64!"; }

    virtual void writeTo(char *target);
    virtual void writeTo(std::string &target);
    virtual std::string getData();

    virtual cs_insn *getCapstone() { return nullptr; }

    Instruction *getSource() const { return source; }
    std::string getMnemonic() const { return mnemonic; }
private:
    diff_t calculateDisplacement();
};

class ReturnInstruction : public DisassembledInstruction {
public:
    ReturnInstruction(const DisassembledStorage &storage) : DisassembledInstruction(storage) {}
};


enum InstructionMode {
    AARCH64_Enc_ADRP,
    AARCH64_Enc_B,
    AARCH64_Enc_BCOND,
    NUMBER_OF_MODES
};

typedef struct AARCH64_ImmInfo {
#if 0
    uint32_t immMask1;
    uint32_t immMask2;
    size_t   immLShift1;
    size_t   immRShift1;
    size_t   immLShift2;
    size_t   immRShift2;
    size_t   dispShift;
#else
    uint32_t fixedMask;
    uint32_t (*makeImm)(address_t, address_t);
#endif
}AARCH64_ImmInfo_t;


class PCRelativeInstruction : public LinkDecorator<InstructionSemantic> {
private:
    Instruction *source;
    std::string mnemonic;
    int mode;
    uint32_t fixedBytes;
    const size_t instructionSize = 4;
    AARCH64_ImmInfo_t immInfo[NUMBER_OF_MODES];

public:
    PCRelativeInstruction(Instruction *source, std::string mnemonic, InstructionMode mode, uint8_t *bytes)
        : source(source), mnemonic(mnemonic), mode(mode),
          immInfo {
              /* ADRP */
              {0x9000001F, [] (address_t dest, address_t src) {
                                diff_t disp = dest - (src & ~0xFFF);
                                uint32_t imm = disp >> 12;
                                return (((imm & 0x3) << 29) | ((imm & 0x1FFFFC) << 3));
                            }
              },
              /* B */
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
          } {
            std::memcpy(&fixedBytes, bytes, instructionSize);
            fixedBytes &= immInfo[static_cast<int>(mode)].fixedMask;
        }

    virtual size_t getSize() const { return instructionSize; }
    virtual void setSize(size_t value)
        { throw "Size is constant for AARCH64!"; }

    virtual void writeTo(char *target) { *reinterpret_cast<uint32_t *>(target) = rebuild(); }
    virtual void writeTo(std::string &target) { target.append(reinterpret_cast<const char *>(rebuild()), instructionSize); }
    virtual std::string getData() { std::string data; writeTo(data); return data; }

    virtual cs_insn *getCapstone() { return nullptr; }

    Instruction *getSource() const { return source; }
    std::string getMnemonic() const { return mnemonic; }
    bool isControlFlowInstruction() const { return (mode >= AARCH64_Enc_B); }
    int getMode() const { return mode; }

    uint32_t rebuild(void);
};
#endif

#endif
