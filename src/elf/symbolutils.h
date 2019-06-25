#ifndef EGALITO_ELF_SYMBOL_UTILS_H
#define EGALITO_ELF_SYMBOL_UTILS_H

#include "exefile/symbol.h"
#include "types.h"
#include "elfxx.h"

class ExeMap;
class SymbolClassifier {
private:
    bool isElf;
public:
    SymbolClassifier(ExeMap *exeMap);
    
    bool isFunction(Symbol *symbol) const;
    bool isMarker(Symbol *symbol) const;
};

class SymbolBuilder {
public:
    static unsigned char typeFromInternalToElf(Symbol::SymbolType type);
    static Symbol::SymbolType typeFromElfToInternal(unsigned char type);
    static unsigned char bindFromInternalToElf(Symbol::BindingType bind);
    static Symbol::BindingType bindFromElfToInternal(unsigned char bind);

    static SymbolList *buildSymbolList(ElfMap *elfMap, std::string symbolFile);
    static SymbolList *buildSymbolList(ElfMap *elfMap);
    static SymbolList *buildDynamicSymbolList(ElfMap *elfMap);
private:
    static SymbolList *buildAnySymbolList(ElfMap *elfMap,
        const char *sectionName, unsigned sectionType);
    static Symbol *findSizeZero(SymbolList *list, const char *sym);
};

#endif
