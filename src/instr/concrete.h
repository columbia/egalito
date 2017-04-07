#ifndef EGALITO_INSTR_CONCRETE_H
#define EGALITO_INSTR_CONCRETE_H

#include "semantic.h"
#include "register.h"

typedef SemanticImpl<RawByteStorage> RawInstruction;
typedef SemanticImpl<DisassembledStorage> DisassembledInstruction;

#ifdef ARCH_X86_64
typedef LinkDecorator<SemanticImpl<DisassembledStorage>> PCRelativeInstruction;

class ControlFlowInstruction : public LinkDecorator<InstructionSemantic> {
private:
    unsigned int id;
    Instruction *source;
    std::string opcode;
    std::string mnemonic;
    int displacementSize;
public:
    ControlFlowInstruction(unsigned int id, Instruction *source,
        std::string opcode, std::string mnemonic, int displacementSize)
        : id(id), source(source), opcode(opcode), mnemonic(mnemonic),
        displacementSize(displacementSize) {}

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

    // the following should only be called by PromoteJumpsPass
    int getId() const { return id; }
    void setDisplacementSize(int ds) { displacementSize = ds; }
    void setOpcode(const std::string &string) { opcode = string; }
    void setMnemonic(const std::string &string) { mnemonic = string; }
public:
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

typedef PCRelativeInstruction PCRelativePageInstruction;

class RelocationInstruction : public InstructionRebuilder {
public:
    RelocationInstruction(Instruction *source, const Assembly &assembly)
        : InstructionRebuilder(source, getMode(assembly), assembly) {}
private:
    InstructionRebuilder::Mode getMode(const Assembly &assembly);
};
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
