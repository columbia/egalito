#ifndef EGALITO_CHUNK_INSTRUCTION_H
#define EGALITO_CHUNK_INSTRUCTION_H

#include <string>
#include <capstone/capstone.h>  // for cs_insn

class ProcessedInstruction;
class UnprocessedInstruction;
class ControlFlowInstruction;

class SemanticVisitor {
public:
    virtual ~SemanticVisitor() {}
    virtual void visit(ProcessedInstruction *semantic) = 0;
    virtual void visit(UnprocessedInstruction *semantic) = 0;
    virtual void visit(ControlFlowInstruction *semantic) = 0;
};

/** Abstract base class for special instruction data.
*/
class InstructionSemantic {
public:
    virtual ~InstructionSemantic() {}

    virtual size_t getSize() const = 0;
    virtual void setSize(size_t value) = 0;

    virtual void writeTo(char *target) = 0;
    virtual void writeTo(std::string &target) = 0;
    virtual std::string getData() = 0;

    virtual void accept(SemanticVisitor *visitor) = 0;
};

class SemanticImpl : public InstructionSemantic {
public:
    virtual void setSize(size_t value);
    virtual std::string getData();
};
class NormalSemanticImpl : public SemanticImpl {
private:
    cs_insn insn;
public:
    NormalSemanticImpl(const cs_insn &insn) : insn(insn) {}

    virtual size_t getSize() const { return insn.size; }

    virtual void writeTo(char *target);
    virtual void writeTo(std::string &target);

    const uint8_t *getBytes() const { return insn.bytes; }
};

template <typename DerivedType, typename BaseType>
class VisitorDecorator : public BaseType {
public:
    virtual void accept(SemanticVisitor *visitor)
        { visitor->visit(static_cast<DerivedType *>(this)); }
};

// concrete classes follow

class ProcessedInstruction : public VisitorDecorator<
    ProcessedInstruction, NormalSemanticImpl> {
public:
};

class UnprocessedInstruction : public VisitorDecorator<
    UnprocessedInstruction, SemanticImpl> {
private:
    std::string rawData;
public:
    virtual size_t getSize() const { return rawData.size(); }

    virtual void writeTo(char *target);
    virtual void writeTo(std::string &target);
    virtual std::string getData() { return rawData; }

    //virtual void accept(SemanticVisitor *visitor) { visitor->visit(this); }
};

class Link;
class ControlFlowInstruction : public VisitorDecorator<
    ControlFlowInstruction, InstructionSemantic> {
private:
    std::string opcode;
    int displacementSize;
    Link *target;
public:
    ControlFlowInstruction() : target(nullptr) {}
    ControlFlowInstruction(Link *target) : target(target) {}

    virtual size_t getSize() const { return opcode.size() + displacementSize; }
};

#endif
