#include <cassert>
#include "jumptable.h"
#include "visitor.h"
#include "analysis/jumptable.h"
#include "instr/concrete.h"
#include "elf/elfmap.h"
#include "log/log.h"

void JumpTableEntry::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}

JumpTable::JumpTable(ElfMap *elf, JumpTableDescriptor *descriptor)
    : descriptor(descriptor) {

    setPosition(PositionFactory::getInstance()
        ->makeAbsolutePosition(descriptor->getAddress()));
}

Function *JumpTable::getFunction() const {
    return descriptor->getFunction();
}

std::vector<Instruction *> JumpTable::getJumpInstructionList() const {
    return jumpInstrList;
}

long JumpTable::getEntryCount() const {
    return descriptor->getEntries();
}

void JumpTable::addJumpInstruction(Instruction *instr) {
    jumpInstrList.push_back(instr);

    auto v = dynamic_cast<IndirectJumpInstruction *>(instr->getSemantic());
    assert(v != nullptr);

    v->addJumpTable(this);
    LOG(10, "OK, instr " << instr->getName()
        << " knows about jump table: " << this);
}

void JumpTable::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}

void JumpTableList::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}
