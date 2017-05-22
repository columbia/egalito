#include "jumptable.h"
#include "visitor.h"
#include "analysis/jumptable.h"
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

Instruction *JumpTable::getInstruction() const {
    return descriptor->getInstruction();
}

long JumpTable::getEntryCount() const {
    return descriptor->getEntries();
}

void JumpTable::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}

void JumpTableList::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}
