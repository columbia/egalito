#ifndef EGALITO_DISASM_OBJECT_ORIENTED_H
#define EGALITO_DISASM_OBJECT_ORIENTED_H

#include "elf/elfmap.h"
#include "elf/symbol.h"
#include "chunk/vtable.h"

class Module;

class DisassembleVTables {
public:
    VTableList *makeVTableList(ElfMap *elfMap, SymbolList *symbolList,
        Module *module);
private:
    VTable *makeVTable(ElfMap *elfMap, Module *module,
        Symbol *vtableSymbol, Symbol *typeinfoSymbol, Symbol *stringSymbol);
};

#endif
