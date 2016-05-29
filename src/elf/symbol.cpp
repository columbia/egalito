#include "symbol.h"

bool SymbolList::add(Symbol *symbol) {
    auto it = lookup.find(symbol->getName());
    if(it != lookup.end()) return false;

    lookup[symbol->getName()] = symbol;
    return true;
}

Symbol *SymbolList::find(const char *name) {
    auto it = lookup.find(name);
    if(it != lookup.end()) {
        return (*it).second;
    }
    else {
        return nullptr;
    }
}
