#include "function.h"
#include "visitor.h"
#include "elf/symbol.h"

std::string Function::getName() const {
    return symbol->getName();
}

bool Function::hasName(std::string name) const {
    if(symbol->getName() == name) return true;
    for(auto s : getSymbol()->getAliases()) {
        if(std::string(s->getName()) == name) {
            return true;
        }
    }

    return false;
}

void Function::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}

void FunctionList::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}
