#ifndef EGALITO_INSTR_LINKED_X86_64_H
#define EGALITO_INSTR_LINKED_X86_64_H

#include "semantic.h"
#include "isolated.h"

// Defines LinkedInstruction and ControlFlowInstruction for x86_64.

#ifdef ARCH_X86_64
class Module;

class LinkedInstruction : public LinkDecorator<DisassembledInstruction> {
private:
    Instruction *instruction;
    int opIndex;
public:
    LinkedInstruction(Instruction *i, const Assembly &assembly)
        : LinkDecorator<DisassembledInstruction>(assembly),
        instruction(i), opIndex(-1) {}

    virtual void writeTo(char *target);
    virtual void writeTo(std::string &target);
    virtual std::string getData();

    void regenerateAssembly();

    void setIndex(int index) { opIndex = index; }

    static LinkedInstruction *makeLinked(Module *module,
        Instruction *instruction, Assembly *assembly);
protected:
    Instruction *getInstruction() const { return instruction; }
    int getDispSize();
    unsigned calculateDisplacement();
};

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
#endif

#endif
