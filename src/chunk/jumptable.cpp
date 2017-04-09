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
    if(getEntryCount() >= 0) makeChildren(elf);
}

Function *JumpTable::getFunction() const {
    return descriptor->getFunction();
}

long JumpTable::getEntryCount() const {
    return descriptor->getEntries();
}

void JumpTable::makeChildren(ElfMap *elf) {
    int count = getEntryCount();
    if(count < 0) {
        LOG(1, "Warning: can't make jump table entries for table "
            << getAddress() << ", bounds are not known");
        return;
    }

    LOG(1, "examining jump table at " << getAddress());
    for(int i = 0; i < count; i ++) {
        auto p = elf->getRWCopyBaseAddress()
            + getAddress() + i*descriptor->getScale();
        //LOG(1, "jump table entry " << i << " value "
        //    << *reinterpret_cast<int *>(p));
        //auto link = new NormalLink();
        //new JumpTableEntry(link)
    }
}

void JumpTable::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}

void JumpTableList::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}
