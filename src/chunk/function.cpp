#include <sstream>
#include <iomanip>
#include "function.h"
#include "visitor.h"
#include "elf/symbol.h"

void Function::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}

std::string FunctionFromSymbol::getName() const {
    return symbol->getName();
}

bool FunctionFromSymbol::hasName(std::string name) const {
    if(symbol->getName() == name) return true;
    for(auto s : getSymbol()->getAliases()) {
        if(std::string(s->getName()) == name) {
            return true;
        }
    }

    return false;
}

FuzzyFunction::FuzzyFunction(address_t originalAddress) {
    std::ostringstream stream;
    stream << "fuzzyfunc-0x" << std::hex << originalAddress;
    name = stream.str();
}

void FunctionList::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}
