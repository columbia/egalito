#include "vtable.h"
#include "visitor.h"

std::string VTable::getName() const {
    return "vtable for " + className;
}

void VTable::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}

void VTableList::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}
