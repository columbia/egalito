#ifndef EGALITO_PE_SYMBOLPARSER_H
#define EGALITO_PE_SYMBOLPARSER_H

#ifdef USE_WIN64_PE

#include <vector>
#include <string>
#include "types.h"
#include "elf/symbol.h"

class PEMap;

class PESymbolParser {
private:
    PEMap *map;
public:
    PESymbolParser(PEMap *map) : map(map) {}
    SymbolList *buildSymbolList(const std::string &symbolFile);
private:
    Symbol *makeSymbol(address_t address, size_t size,
        const std::string &tag, const std::string &name, size_t index);
};

#endif  // USE_WIN64_PE
#endif
