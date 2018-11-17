#ifndef EGALITO_INSTR_VISITOR_H
#define EGALITO_INSTR_VISITOR_H

class IsolatedInstruction;
class LinkedInstruction;
class ControlFlowInstruction;
class DataLinkedControlFlowInstruction;
class ReturnInstruction;
class IndirectJumpInstruction;
class IndirectCallInstruction;
class StackFrameInstruction;
class LiteralInstruction;
class LinkedLiteralInstruction;

class InstructionVisitor {
public:
    virtual ~InstructionVisitor() {}
    virtual void visit(IsolatedInstruction *isolated) = 0;
    virtual void visit(LinkedInstruction *linked) = 0;
    virtual void visit(ControlFlowInstruction *controlFlow) = 0;
    #ifdef ARCH_X86_64
    virtual void visit(DataLinkedControlFlowInstruction *dataLinked) = 0;
    #endif
    virtual void visit(ReturnInstruction *retInstr);
    virtual void visit(IndirectJumpInstruction *indirect);
    virtual void visit(IndirectCallInstruction *indirect);
    virtual void visit(StackFrameInstruction *stackFrame) = 0;
    virtual void visit(LiteralInstruction *literal) = 0;
    virtual void visit(LinkedLiteralInstruction *literal) = 0;
};

class InstructionListener : public InstructionVisitor {
public:
    virtual void visit(IsolatedInstruction *isolated) {}
    virtual void visit(LinkedInstruction *linked) {}
    virtual void visit(ControlFlowInstruction *controlFlow) {}
};

#endif
