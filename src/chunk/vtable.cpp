#include "vtable.h"
#include "visitor.h"

void VTableEntry::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}

std::string VTable::getName() const {
    return "vtable for " + className;
}

void VTable::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}

void VTableList::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}
