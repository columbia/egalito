#ifndef EGALITO_CHUNK_INSTRUCTION_H
#define EGALITO_CHUNK_INSTRUCTION_H

#include <cstring>
#include <string>
#include <utility>  // for std::move
#include <capstone/capstone.h>  // for cs_insn
#include "register.h"
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

/** Stores a complete copy of the capstone data for an instruction.

    This involves allocating memory for capstone details, so this class
    has its copy constructor disabled and can only be moved.
*/
class DisassembledStorage {
private:
    cs_insn insn;
    cs_detail *detail;
private:
    DisassembledStorage(const DisassembledStorage &other);
public:
    DisassembledStorage(const cs_insn &insn);
    DisassembledStorage(DisassembledStorage &&other);
    ~DisassembledStorage();

    DisassembledStorage &operator = (DisassembledStorage &&other);

    size_t getSize() const { return insn.size; }

    void writeTo(char *target);
    void writeTo(std::string &target);
    std::string getData();

    cs_insn *getCapstone() { return &insn; }
};

template <typename Storage>
class SemanticImpl : public InstructionSemantic {
private:
    Storage storage;
public:
    SemanticImpl(Storage &&storage) : storage(std::move(storage)) {}

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
protected:
    void setStorage(Storage &&storage) { this->storage = std::move(storage); }
};

template <typename BaseType>
class LinkDecorator : public BaseType {
private:
    Link *link;
public:
    LinkDecorator() : link(nullptr) {}

    template <typename Storage>
    LinkDecorator(Storage &&storage) : BaseType(std::move(storage)) {}

    virtual Link *getLink() const { return link; }
    virtual void setLink(Link *link) { this->link = link; }
};

// --- concrete classes follow ---

typedef SemanticImpl<RawByteStorage> RawInstruction;
typedef SemanticImpl<DisassembledStorage> DisassembledInstruction;

#ifdef ARCH_X86_64
typedef LinkDecorator<SemanticImpl<DisassembledStorage>> RelocationInstruction;
typedef LinkDecorator<SemanticImpl<DisassembledStorage>> PCRelativeInstruction;

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
#elif defined(ARCH_AARCH64)
enum InstructionMode {
    AARCH64_IM_ADRP = 0,
    AARCH64_IM_ADDIMM,
    AARCH64_IM_LDR,
    AARCH64_IM_BL,
    AARCH64_IM_B,
    AARCH64_IM_BCOND,
    AARCH64_IM_CBZ,
    AARCH64_IM_CBNZ,
    AARCH64_IM_TBZ,
    AARCH64_IM_TBNZ,
    AARCH64_IM_MAX
};

typedef struct AARCH64_ImInfo_t {
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
    int immediateIndex;
#endif
}AARCH64_ImInfo_t;

extern const AARCH64_ImInfo_t AARCH64_ImInfo[AARCH64_IM_MAX];

class InstructionRebuilder : public LinkDecorator<InstructionSemantic> {
private:
    Instruction *source;
    std::string mnemonic;
    uint32_t fixedBytes;
    int64_t originalOffset;
    const size_t instructionSize = 4;
    const AARCH64_ImInfo_t *imInfo;
public:
    InstructionRebuilder(Instruction *source, InstructionMode mode, const cs_insn &insn)
        : source(source), mnemonic(insn.mnemonic), imInfo(&AARCH64_ImInfo[mode]) {
            std::memcpy(&fixedBytes, insn.bytes, instructionSize);
            fixedBytes &= AARCH64_ImInfo[mode].fixedMask;

            cs_arm64 *x = &insn.detail->arm64;
            originalOffset = x->operands[AARCH64_ImInfo[mode].immediateIndex].imm;
        }

    virtual size_t getSize() const { return instructionSize; }
    virtual void setSize(size_t value)
        { throw "Size is constant for AARCH64!"; }

    virtual void writeTo(char *target);
    virtual void writeTo(std::string &target);
    virtual std::string getData();

    virtual cs_insn *getCapstone() { return nullptr; }

    Instruction *getSource() const { return source; }
    std::string getMnemonic() const { return mnemonic; }

    int getMode() const { return imInfo - AARCH64_ImInfo; }
    uint32_t getFixedBytes() const { return fixedBytes; }
    uint32_t getOriginalOffset() const { return originalOffset; }

    virtual uint32_t rebuild(void);
};

class ControlFlowInstruction : public InstructionRebuilder {
public:
    ControlFlowInstruction(Instruction *source, const cs_insn &insn)
        : InstructionRebuilder(source, decodeMode(insn), insn) {}
private:
    static InstructionMode decodeMode(const cs_insn &insn);
};

class PCRelativeInstruction : public InstructionRebuilder {
public:
    PCRelativeInstruction(Instruction *source, const cs_insn &insn)
        : InstructionRebuilder(source, decodeMode(insn), insn) {}
private:
    static InstructionMode decodeMode(const cs_insn &insn);
};

typedef PCRelativeInstruction RelocationInstruction;
#endif

class ReturnInstruction : public SemanticImpl<DisassembledStorage> {
public:
    ReturnInstruction(const cs_insn &insn)
        : SemanticImpl<DisassembledStorage>(insn) {}
};

class IndirectJumpInstruction : public SemanticImpl<DisassembledStorage> {
private:
    Register reg;
    std::string mnemonic;
public:
    IndirectJumpInstruction(const cs_insn &insn, Register reg,
        const std::string &mnemonic)
        : SemanticImpl<DisassembledStorage>(insn), reg(reg),
        mnemonic(mnemonic) {}

    std::string getMnemonic() const { return mnemonic; }
    register_t getRegister() const { return reg; }
};

class InferredInstruction : public LinkDecorator<SemanticImpl<DisassembledStorage>> {
private:
    Instruction *instruction;
public:
    InferredInstruction(Instruction *i, const cs_insn &insn)
        : LinkDecorator<SemanticImpl<DisassembledStorage>>(insn),
        instruction(i) {}

    virtual void writeTo(char *target);
    virtual void writeTo(std::string &target);
    virtual std::string getData();

    void regenerateCapstone();
};

#endif
