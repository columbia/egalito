#ifndef EGALITO_DISASM_OBJECT_ORIENTED_H
#define EGALITO_DISASM_OBJECT_ORIENTED_H

#include "elf/elfmap.h"
#include "elf/symbol.h"
#include "elf/reloc.h"
#include "chunk/vtable.h"

class Module;
class Program;

class DisassembleVTables {
public:
    VTableList *makeVTableList(ElfMap *elfMap, SymbolList *symbolList,
        RelocList *relocList, Module *module, Program *program);
private:
    VTable *makeVTable(ElfMap *elfMap, SymbolList *symbolList,
        RelocList *relocList, Module *module, Program *program,
        Symbol *vtableSymbol, Symbol *typeinfoSymbol, Symbol *stringSymbol);
};

#endif
