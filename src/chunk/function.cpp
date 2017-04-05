#include "function.h"
#include "visitor.h"
#include "elf/symbol.h"

std::string Function::getName() const {
    return symbol->getName();
}

void Function::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}

void FunctionList::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}
