#ifndef EGALITO_GENERATE_CONCRETE_DEFERRED_H
#define EGALITO_GENERATE_CONCRETE_DEFERRED_H

#include "deferred.h"
#include "elf/elfxx.h"

class Section2;
class Symbol;
class Function;

class SymbolTableContent : public DeferredMap<Symbol *, ElfXX_Sym> {
public:
    typedef DeferredValueImpl<ElfXX_Sym> DeferredType;
public:
    DeferredType *add(Function *func, Symbol *sym, size_t strndx);
    /** Special-case add used for adding SECTION symbols. */
    void add(Symbol *sym, bool atFront = false);
    void add(ElfXX_Sym *symbol);
};

class ShdrTableContent : public DeferredMap<Section2 *, ElfXX_Shdr> {
public:
    typedef DeferredValueImpl<ElfXX_Shdr> DeferredType;
public:
    DeferredType *add(Section2 *section);
};

#endif
