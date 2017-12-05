#ifndef EGALITO_INSTR_LINKED_X86_64_H
#define EGALITO_INSTR_LINKED_X86_64_H

#include "semantic.h"
#include "isolated.h"

// Defines LinkedInstruction, ControlFlowInstruction, etc for x86_64.

#ifdef ARCH_X86_64
class Instruction;
class Module;

class LinkedInstruction : public LinkDecorator<SemanticImpl> {
private:
    Instruction *instruction;
    int opIndex;
public:
    LinkedInstruction(Instruction *i) : instruction(i), opIndex(-1) {}

    void writeTo(char *target, bool useDisp);
    void writeTo(std::string &target, bool useDisp);
    int getDispOffset() const;

    void regenerateAssembly();

    void setIndex(int index) { opIndex = index; }
    int getIndex() const { return opIndex; }

    // should be only necessary in insertBeforeJumpTo
    void setInstruction(Instruction *instruction)
        { this->instruction = instruction; }

    static LinkedInstruction *makeLinked(Module *module,
        Instruction *instruction, AssemblyPtr assembly);

    virtual void accept(InstructionVisitor *visitor) { visitor->visit(this); }
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
    bool nonreturn;
public:
    ControlFlowInstruction(unsigned int id, Instruction *source,
        std::string opcode, std::string mnemonic, int displacementSize)
        : id(id), source(source), opcode(opcode), mnemonic(mnemonic),
        displacementSize(displacementSize), nonreturn(false) {}

    virtual size_t getSize() const { return opcode.size() + displacementSize; }
    virtual void setSize(size_t value);

    virtual const std::string &getData() const
        { throw "Can't call getData() on ControlFlowInstruction"; }

    void writeTo(char *target, bool useDisp);
    void writeTo(std::string &target, bool useDisp);
    int getDispOffset() const { return opcode.size(); }

    virtual AssemblyPtr getAssembly() { return AssemblyPtr(); }
    virtual void setAssembly(AssemblyPtr assembly)
        { throw "Can't call setAssembly() on ControlFlowInstruction"; }

    virtual void accept(InstructionVisitor *visitor) { visitor->visit(this); }

    Instruction *getSource() const { return source; }
    std::string getMnemonic() const { return mnemonic; }
    std::string getOpcode() const { return opcode; }
    int getDisplacementSize() const { return displacementSize; }
    bool returns() const { return !nonreturn; }
    void setNonreturn() { nonreturn = true; }

    // the following should only be called by PromoteJumpsPass
    int getId() const { return id; }
    void setDisplacementSize(int ds) { displacementSize = ds; }
    void setOpcode(const std::string &string) { opcode = string; }
    void setMnemonic(const std::string &string) { mnemonic = string; }
public:
    diff_t calculateDisplacement();
};

// no link yet
class StackFrameInstruction : public SemanticImpl {
private:
    unsigned int id;
    size_t opCodeSize;
    size_t displacementSize;
    long int displacement;
public:
    StackFrameInstruction(AssemblyPtr assembly);

    virtual size_t getSize() const { return opCodeSize + displacementSize; }

    virtual AssemblyPtr getAssembly() { return AssemblyPtr(); }
    virtual void setAssembly(AssemblyPtr assembly)
        { throw "Can't call setAssembly() on StackFrameInstruction"; }

    virtual Link *getLink() const { return nullptr; }
    virtual void setLink(Link *link)
        { throw "Can't call setLink() on StackFrameInstruction"; }

    void writeTo(char *target);
    void writeTo(std::string &target);

    virtual void accept(InstructionVisitor *visitor) { visitor->visit(this); }

    int getId() const { return id; }
    void addToDisplacementValue(long int add);
};

// not used for X86, but we need a definition for visitors
class LinkedLiteralInstruction : public SemanticImpl {
public:
};
#endif

#endif
