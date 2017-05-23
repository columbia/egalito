#ifndef EGALITO_INSTR_VISITOR_H
#define EGALITO_INSTR_VISITOR_H

template <typename Storage>
class SemanticImpl;
class RawByteStorage;
class DisassembledStorage;

typedef SemanticImpl<RawByteStorage> RawInstruction;
typedef SemanticImpl<DisassembledStorage> DisassembledInstruction;
typedef DisassembledInstruction IsolatedInstruction;

class LinkedInstruction;
class ControlFlowInstruction;
class ReturnInstruction;
class IndirectJumpInstruction;
class IndirectCallInstruction;
class LiteralInstruction;

class InstructionVisitor {
public:
    virtual ~InstructionVisitor() {}
    virtual void visit(RawInstruction *raw) = 0;
    virtual void visit(IsolatedInstruction *isolated) = 0;
    virtual void visit(LinkedInstruction *linked) = 0;
    virtual void visit(ControlFlowInstruction *controlFlow) = 0;
    virtual void visit(ReturnInstruction *retInstr);
    virtual void visit(IndirectJumpInstruction *indirect);
    virtual void visit(IndirectCallInstruction *indirect);
    virtual void visit(LiteralInstruction *literal) = 0;
};

class InstructionListener : public InstructionVisitor {
public:
    virtual void visit(RawInstruction *raw) {}
    virtual void visit(IsolatedInstruction *isolated) {}
    virtual void visit(LinkedInstruction *linked) {}
    virtual void visit(ControlFlowInstruction *controlFlow) {}
};

#endif
