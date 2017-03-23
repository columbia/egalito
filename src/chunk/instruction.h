#ifndef EGALITO_CHUNK_INSTRUCTION_H
#define EGALITO_CHUNK_INSTRUCTION_H

#include <cstring>
#include <string>
#include <utility>  // for std::move
#include <capstone/capstone.h>  // for cs_insn
#include <disasm/assembly.h>
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

    virtual Assembly *getAssembly() = 0;
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

    Assembly *getAssembly() { return nullptr; }
};

/** Stores a complete copy of the capstone data for an instruction.

    This involves allocating memory for capstone details, so this class
    has its copy constructor disabled and can only be moved.
*/
class DisassembledStorage {
private:
    Assembly assembly;
private:
    DisassembledStorage(const DisassembledStorage &other);
    DisassembledStorage &operator = (DisassembledStorage &other);
public:
    DisassembledStorage(const Assembly &assembly)
        : assembly(assembly) {}
    DisassembledStorage(DisassembledStorage &&other);
    ~DisassembledStorage();

    DisassembledStorage &operator = (DisassembledStorage &&other);

    size_t getSize() const { return assembly.getSize(); }

    void writeTo(char *target);
    void writeTo(std::string &target);
    std::string getData();

    Assembly *getAssembly() { return &assembly; }
};

template <typename Storage>
class SemanticImpl : public InstructionSemantic {
private:
    Storage storage;
public:
    SemanticImpl(Storage &&storage) : storage(std::move(storage)) {}

    Storage &getStorage() { return storage; }
    Storage &&moveStorageFrom() { return std::move(storage); }

    virtual size_t getSize() const { return storage.getSize(); }
    virtual void setSize(size_t value)
        { throw "Can't set size for this instruction type!"; }

    virtual Link *getLink() const { return nullptr; }
    virtual void setLink(Link *newLink)
        { throw "Can't set link for this instruction type!"; }

    virtual void writeTo(char *target) { storage.writeTo(target); }
    virtual void writeTo(std::string &target) { storage.writeTo(target); }
    virtual std::string getData() { return storage.getData(); }

    virtual Assembly *getAssembly() { return storage.getAssembly(); }
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

    virtual Assembly *getAssembly() { return nullptr; }

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
    const AARCH64_modeInfo_t *modeInfo;
    Assembly assembly;

public:
    InstructionRebuilder(Instruction *source, Mode mode,
                         const Assembly &assembly);

    virtual size_t getSize() const { return assembly.getSize(); }
    virtual void setSize(size_t value)
        { throw "Size is constant for AARCH64!"; }

    virtual void writeTo(char *target);
    virtual void writeTo(std::string &target);
    virtual std::string getData();

    virtual Assembly *getAssembly();

    Instruction *getSource() const { return source; }
    std::string getMnemonic() const { return assembly.getMnemonic(); }

    const AARCH64_modeInfo_t *getModeInfo() const { return modeInfo; }
    uint32_t getOriginalOffset() const;

    virtual uint32_t rebuild(void);

private:
    Assembly generateAssembly();
};

class ControlFlowInstruction : public InstructionRebuilder {
public:
    ControlFlowInstruction(Instruction *source, const Assembly &assembly)
        : InstructionRebuilder(source, getMode(assembly), assembly) {}
private:
    InstructionRebuilder::Mode getMode(const Assembly &assembly);
};

// This semantic is used for code pointers in .got section. An example case
// is in _start for PIE. This semantics adjust the offset to .got and
// another pass adjusts the actual data in .got.
class PCRelativeInstruction : public InstructionRebuilder {
public:
    PCRelativeInstruction(Instruction *source, const Assembly &assembly)
        : InstructionRebuilder(source, getMode(assembly), assembly) {}
private:
    InstructionRebuilder::Mode getMode(const Assembly &assembly);
};

typedef PCRelativeInstruction RelocationInstruction;
#endif

class ReturnInstruction : public SemanticImpl<DisassembledStorage> {
public:
    ReturnInstruction(const Assembly &assembly)
        : SemanticImpl<DisassembledStorage>(assembly) {}
};

class IndirectJumpInstruction : public SemanticImpl<DisassembledStorage> {
private:
    Register reg;
    std::string mnemonic;
public:
    IndirectJumpInstruction(const Assembly &assembly, Register reg,
        const std::string &mnemonic)
        : SemanticImpl<DisassembledStorage>(assembly), reg(reg),
        mnemonic(mnemonic) {}

    std::string getMnemonic() const { return mnemonic; }
    register_t getRegister() const { return reg; }
};

class LinkedInstruction : public LinkDecorator<SemanticImpl<DisassembledStorage>> {
private:
    Instruction *instruction;
    int opIndex;
public:
    LinkedInstruction(Instruction *i, const Assembly &assembly, int opIndex)
        : LinkDecorator<SemanticImpl<DisassembledStorage>>(assembly),
        instruction(i), opIndex(opIndex) {}
    LinkedInstruction(Instruction *i, DisassembledStorage &&other, int opIndex)
        : LinkDecorator<SemanticImpl<DisassembledStorage>>(other),
        instruction(i), opIndex(opIndex) {}

    virtual void writeTo(char *target);
    virtual void writeTo(std::string &target);
    virtual std::string getData();

    void regenerateAssembly();
protected:
    Instruction *getInstruction() const { return instruction; }
    int getDispSize();
    virtual unsigned calculateDisplacement();
};

#ifdef ARCH_X86_64
class RelocationInstruction : public LinkedInstruction {
public:
    RelocationInstruction(Instruction *i, const Assembly &assembly, int opIndex)
        : LinkedInstruction(i, assembly, opIndex) {}
    RelocationInstruction(Instruction *i, DisassembledStorage &&other, int opIndex)
        : LinkedInstruction(i, std::move(other), opIndex) {}
};
#endif

class InferredInstruction : public LinkedInstruction {
private:
    Instruction *instruction;
public:
    InferredInstruction(Instruction *i, const Assembly &assembly, int opIndex)
        : LinkedInstruction(i, assembly, opIndex) {}
    InferredInstruction(Instruction *i, DisassembledStorage &&other, int opIndex)
        : LinkedInstruction(i, std::move(other), opIndex) {}
};

class AbsoluteLinkedInstruction : public LinkedInstruction {
public:
    AbsoluteLinkedInstruction(Instruction *i, const Assembly &assembly, int opIndex)
        : LinkedInstruction(i, assembly, opIndex) {}
    AbsoluteLinkedInstruction(Instruction *i, DisassembledStorage &&other, int opIndex)
        : LinkedInstruction(i, std::move(other), opIndex) {}
protected:
    virtual unsigned calculateDisplacement();
};

#endif
