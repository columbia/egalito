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
    std::string getOpcode() const { return opcode; }
    int getDisplacementSize() const { return displacementSize; }
private:
    diff_t calculateDisplacement();
};
#elif defined(ARCH_AARCH64)
class InstructionRebuilder : public LinkDecorator<InstructionSemantic> {
public:
    enum Mode {
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

private:
    typedef struct AARCH64_modeInfo_t {
        uint32_t fixedMask;
        uint32_t (*makeImm)(address_t, address_t);
        int immediateIndex;
    }AARCH64_modeInfo_t;

    const static AARCH64_modeInfo_t AARCH64_ImInfo[AARCH64_IM_MAX];

    Instruction *source;
    std::string mnemonic;
    uint32_t fixedBytes;
    int64_t originalOffset;
    const size_t size = 4;
    const AARCH64_modeInfo_t *modeInfo;
public:
    InstructionRebuilder(Instruction *source, Mode mode, const cs_insn &insn);

    virtual size_t getSize() const { return size; }
    virtual void setSize(size_t value)
        { throw "Size is constant for AARCH64!"; }

    virtual void writeTo(char *target);
    virtual void writeTo(std::string &target);
    virtual std::string getData();

    virtual cs_insn *getCapstone() { return nullptr; }

    Instruction *getSource() const { return source; }
    std::string getMnemonic() const { return mnemonic; }

    const AARCH64_modeInfo_t *getModeInfo() const { return modeInfo; }
    uint32_t getFixedBytes() const { return fixedBytes; }
    uint32_t getOriginalOffset() const { return originalOffset; }

    virtual uint32_t rebuild(void);
};

class ControlFlowInstruction : public InstructionRebuilder {
public:
    ControlFlowInstruction(Instruction *source, const cs_insn &insn)
        : InstructionRebuilder(source, getMode(insn), insn) {}
private:
    InstructionRebuilder::Mode getMode(const cs_insn &insn);
};

class PCRelativeInstruction : public InstructionRebuilder {
public:
    PCRelativeInstruction(Instruction *source, const cs_insn &insn)
        : InstructionRebuilder(source, getMode(insn), insn) {}
private:
    InstructionRebuilder::Mode getMode(const cs_insn &insn);
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

class LinkedInstruction : public LinkDecorator<SemanticImpl<DisassembledStorage>> {
private:
    Instruction *instruction;
    int opIndex;
public:
    LinkedInstruction(Instruction *i, const cs_insn &insn, int opIndex)
        : LinkDecorator<SemanticImpl<DisassembledStorage>>(insn),
        instruction(i), opIndex(opIndex) {}

    virtual void writeTo(char *target);
    virtual void writeTo(std::string &target);
    virtual std::string getData();

    void regenerateCapstone();
protected:
    Instruction *getInstruction() const { return instruction; }
    int getDispSize();
    virtual unsigned calculateDisplacement();
};

#ifdef ARCH_X86_64
class RelocationInstruction : public LinkedInstruction {
public:
    RelocationInstruction(Instruction *i, const cs_insn &insn, int opIndex)
        : LinkedInstruction(i, insn, opIndex) {}
};
#endif

class InferredInstruction : public LinkedInstruction {
private:
    Instruction *instruction;
public:
    InferredInstruction(Instruction *i, const cs_insn &insn, int opIndex)
        : LinkedInstruction(i, insn, opIndex) {}
};

class AbsoluteLinkedInstruction : public LinkedInstruction {
public:
    AbsoluteLinkedInstruction(Instruction *i, const cs_insn &insn, int opIndex)
        : LinkedInstruction(i, insn, opIndex) {}
protected:
    virtual unsigned calculateDisplacement();
};

#endif
