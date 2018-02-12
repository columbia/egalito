#ifndef EGALITO_INSTR_LINKED_AARCH64_H
#define EGALITO_INSTR_LINKED_AARCH64_H

#include <vector>
#include "semantic.h"
#include "concrete.h"
#include "isolated.h"
#include "chunk/chunkfwd.h"

// Defines LinkedInstruction and ControlFlowInstruction for aarch64.

#if defined(ARCH_AARCH64)
class Reloc;

class LinkedInstruction : public LinkDecorator<SemanticImpl> {
public:
    enum Mode {
        AARCH64_IM_ADRP = 0,
        AARCH64_IM_ADR,
        AARCH64_IM_ADDIMM,
        AARCH64_IM_LDRIMM,
        AARCH64_IM_LDRH,
        AARCH64_IM_LDRB,
        AARCH64_IM_LDRSW,
        AARCH64_IM_LDRSH,
        AARCH64_IM_LDRSB,
        AARCH64_IM_LDRLIT,
        AARCH64_IM_MOV,     /* 10 */
        AARCH64_IM_MOVK,
        AARCH64_IM_STR,
        AARCH64_IM_STRH,
        AARCH64_IM_STRB,
        AARCH64_IM_BL,
        AARCH64_IM_B,
        AARCH64_IM_BCOND,
        AARCH64_IM_CBZ,
        AARCH64_IM_CBNZ,
        AARCH64_IM_TBZ,     /* 20 */
        AARCH64_IM_TBNZ,
        AARCH64_IM_MAX
    };

private:
    struct AARCH64_modeInfo_t {
        uint32_t fixedMask;
        uint32_t (*makeImm)(address_t, address_t, uint32_t);
        int immediateIndex;
    };

    const static AARCH64_modeInfo_t AARCH64_ImInfo[AARCH64_IM_MAX];

    Instruction *instruction;
    const AARCH64_modeInfo_t *modeInfo;

public:
    LinkedInstruction(Instruction *instruction);
    virtual ~LinkedInstruction() {}

    virtual void setAssembly(AssemblyPtr assembly);

    void writeTo(char *target, bool useDisp);
    void writeTo(std::string &target, bool useDisp);

    void regenerateAssembly();

    Instruction *getSource() const { return instruction; }
    std::string getMnemonic() { return getAssembly()->getMnemonic(); }

    const AARCH64_modeInfo_t *getModeInfo() const { return modeInfo; }
    virtual int64_t getOriginalOffset() const;

    uint32_t rebuild();
    bool check();

    // should be only necessary in insertBeforeJumpTo
    void setInstruction(Instruction *instruction)
        { this->instruction = instruction; }

    static LinkedInstruction *makeLinked(Module *module,
        Instruction *instruction, AssemblyPtr assembly, Reloc *reloc,
        bool resolveWeak);
    static void makeAllLinked(Module *module);

    virtual void accept(InstructionVisitor *visitor) { visitor->visit(this); }
private:
    static Mode getMode(const Assembly &assembly);
    static void resolveLinks(Module *module,
        const std::vector<std::pair<Instruction *, address_t>> &list);

    static void saveToFile(Module *module,
        const std::vector<std::pair<Instruction *, address_t>>& list);
    static std::vector<std::pair<Instruction *, address_t>> loadFromFile(
        Module *module);
};

class ControlFlowInstruction : public LinkedInstruction {
private:
    bool nonreturn;
public:
    ControlFlowInstruction(Instruction *instruction)
        : LinkedInstruction(instruction), nonreturn(false) {}

    virtual void accept(InstructionVisitor *visitor) { visitor->visit(this); }

    bool returns() const { return !nonreturn; }
    void setNonreturn() { nonreturn = true; }
};

class LinkedLiteralInstruction : public LinkDecorator<LiteralInstruction> {
public:
    static LinkedLiteralInstruction *makeLinked(Module *module,
        Instruction *instruction, std::string raw, Reloc *reloc,
        bool resolveWeak);

    void writeTo(char *target);
    void writeTo(std::string &target);

    virtual void accept(InstructionVisitor *visitor) { visitor->visit(this); }
private:
    uint32_t relocate();
};

class StackFrameInstruction : public SemanticImpl {
};

#endif

#endif
