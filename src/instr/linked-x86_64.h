#ifndef EGALITO_INSTR_LINKED_X86_64_H
#define EGALITO_INSTR_LINKED_X86_64_H

#include "semantic.h"
#include "isolated.h"

// Defines LinkedInstruction, ControlFlowInstruction, etc for x86_64.

#ifdef ARCH_X86_64
class Instruction;
class Module;
class Reloc;

class LinkedInstructionBase : public LinkDecorator<SemanticImpl> {
private:
    Instruction *instruction;
    int opIndex;
    size_t displacementSize;
    size_t displacementOffset;
public:
    LinkedInstructionBase(Instruction *i) : instruction(i), opIndex(-1),
        displacementSize(0), displacementOffset(0) {}

    void writeTo(char *target, bool useDisp);
    void writeTo(std::string &target, bool useDisp);
    size_t getDispSize() const { return displacementSize; }
    size_t getDispOffset() const { return displacementOffset; }

    void regenerateAssembly();

    void setIndex(int index) { opIndex = index; makeDisplacementInfo(); }
    int getIndex() const { return opIndex; }

    // should be only necessary in insertBeforeJumpTo
    void setInstruction(Instruction *instruction)
        { this->instruction = instruction; }

protected:
    Instruction *getInstruction() const { return instruction; }
    unsigned long calculateDisplacement();
    void makeDisplacementInfo();
};

class LinkedInstruction : public LinkedInstructionBase {
public:
    using LinkedInstructionBase::LinkedInstructionBase;

    static LinkedInstructionBase *makeLinked(Module *module,
        Instruction *instruction, AssemblyPtr assembly);
    static LinkedInstructionBase *makeLinked(Module *module,
        Instruction *instruction, AssemblyPtr assembly, Reloc *reloc);

    virtual void accept(InstructionVisitor *visitor) { visitor->visit(this); }
};

class ControlFlowInstructionBase : public LinkDecorator<InstructionSemantic> {
private:
    unsigned int id;
    Instruction *source;
    std::string opcode;
    std::string mnemonic;
    int displacementSize;
    bool nonreturn;
public:
    ControlFlowInstructionBase(unsigned int id, Instruction *source,
        std::string opcode, std::string mnemonic, int displacementSize)
        : id(id), source(source), opcode(opcode), mnemonic(mnemonic),
        displacementSize(displacementSize), nonreturn(false) {}

    virtual size_t getSize() const { return opcode.size() + displacementSize; }
    virtual void setSize(size_t value);

    virtual const std::string &getData() const
        { throw "Can't call getData() on ControlFlowInstructionBase"; }

    virtual bool isControlFlow() const { return true; }

    void writeTo(char *target, bool useDisp);
    void writeTo(std::string &target, bool useDisp);
    size_t getDispOffset() const { return opcode.size(); }

    virtual AssemblyPtr getAssembly() { return AssemblyPtr(); }
    virtual void setAssembly(AssemblyPtr assembly)
        { throw "Can't call setAssembly() on ControlFlowInstructionBase"; }


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
    void setSource(Instruction *source) { this->source = source; }
    void setMnemonic(const std::string &string) { mnemonic = string; }
public:
    diff_t calculateDisplacement();
};

class ControlFlowInstruction : public ControlFlowInstructionBase {
public:
    using ControlFlowInstructionBase::ControlFlowInstructionBase;

    virtual void accept(InstructionVisitor *visitor) { visitor->visit(this); }
};

class DataLinkedControlFlowInstruction : public LinkedInstructionBase {
private:
    bool isRelative;
public:
    DataLinkedControlFlowInstruction(Instruction *source)
        : LinkedInstructionBase(source), isRelative(true) {}
    DataLinkedControlFlowInstruction(unsigned int id, Instruction *source,
        std::string opcode, std::string mnemonic, int displacementSize);

    bool getIsRelative() const { return isRelative; }
    virtual void setLink(Link *link);  // sets isRelative

    bool isCall() const;
    virtual bool isControlFlow() const { return true; }

    virtual void accept(InstructionVisitor *visitor) { visitor->visit(this); }
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
