#include "visitor.h"
#include "concrete.h"

void InstructionVisitor::visit(ReturnInstruction *retInstr) {
    visit(static_cast<IsolatedInstruction *>(retInstr));
}

void InstructionVisitor::visit(IndirectJumpInstruction *indirect) {
    visit(static_cast<IsolatedInstruction *>(indirect));
}

void InstructionVisitor::visit(IndirectCallInstruction *indirect) {
    visit(static_cast<IsolatedInstruction *>(indirect));
}
