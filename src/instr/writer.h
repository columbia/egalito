#ifndef EGALITO_INSTR_WRITER_H
#define EGALITO_INSTR_WRITER_H

#include <string>
#include "visitor.h"
#include "elf/elfxx.h"
#include "types.h"

class InstrWriterBase : public InstructionVisitor {
protected:
    virtual bool useDisplacements() const { return true; }
};

class InstrWriterCString : public InstrWriterBase {
private:
    char *target;
public:
    InstrWriterCString(char *target) : target(target) {}

    virtual void visit(IsolatedInstruction *isolated);
    virtual void visit(LinkedInstruction *linked);
    virtual void visit(ControlFlowInstruction *controlFlow);
#ifdef ARCH_X86_64
    virtual void visit(DataLinkedControlFlowInstruction *controlFlow);
    virtual void visit(StackFrameInstruction *stackFrame);
#endif
    virtual void visit(LiteralInstruction *literal);
    virtual void visit(LinkedLiteralInstruction *literal);
};

class InstrWriterCppString : public InstrWriterBase {
private:
    std::string &target;
public:
    InstrWriterCppString(std::string &target) : target(target) {}

    virtual void visit(IsolatedInstruction *isolated);
    virtual void visit(LinkedInstruction *linked);
    virtual void visit(ControlFlowInstruction *controlFlow);
#ifdef ARCH_X86_64
    virtual void visit(DataLinkedControlFlowInstruction *controlFlow);
    virtual void visit(StackFrameInstruction *stackFrame);
#endif
    virtual void visit(LiteralInstruction *literal);
    virtual void visit(LinkedLiteralInstruction *literal);
};

class InstrWriterGetData : public InstrWriterBase {
private:
    std::string data;
public:
    std::string get() { return std::move(data); }
    virtual void visit(IsolatedInstruction *isolated);
    virtual void visit(LinkedInstruction *linked);
    virtual void visit(ControlFlowInstruction *controlFlow);
#ifdef ARCH_X86_64
    virtual void visit(DataLinkedControlFlowInstruction *controlFlow);
    virtual void visit(StackFrameInstruction *stackFrame);
#endif
    virtual void visit(LiteralInstruction *literal);
    virtual void visit(LinkedLiteralInstruction *literal);
};

template <typename BaseWriterType>
class InstrWriterWithoutDisplacements : public BaseWriterType {
protected:
    using BaseWriterType::BaseWriterType;
    virtual bool useDisplacements() const { return false; }
};

typedef InstrWriterWithoutDisplacements<InstrWriterCString>
    InstrWriterForObjectFile;

class InstrWriterMakeReloc : public InstructionListener {
public:
    typedef ElfXX_Rela RawRelocType;
private:
    bool madeReloc;
    RawRelocType reloc;
public:
    InstrWriterMakeReloc() : madeReloc(false) {}

    bool hasReloc() const { return madeReloc; }
    RawRelocType &getReloc() { return reloc; }

    virtual void visit(LinkedInstruction *linked);
    virtual void visit(ControlFlowInstruction *controlFlow);
};

#endif
