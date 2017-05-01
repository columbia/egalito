#ifndef EGALITO_GENERATE_CONCRETE_DEFERRED_H
#define EGALITO_GENERATE_CONCRETE_DEFERRED_H

#include <vector>
#include "deferred.h"
#include "elf/elfxx.h"

class Section2;
class SectionRef;
class Symbol;
class Function;
class Chunk;
class Link;
class SectionList;

class SymbolTableContent : public DeferredMap<Symbol *, ElfXX_Sym> {
public:
    typedef DeferredValueImpl<ElfXX_Sym> DeferredType;
private:
    std::vector<DeferredType *> sectionSymbols;
public:
    DeferredType *add(Function *func, Symbol *sym, size_t strndx);
    /** Special-case add used for adding SECTION symbols. */
    void add(Symbol *sym, int index);
    /** Special-case add to insert NULL symbol. */
    void add(ElfXX_Sym *symbol);

    size_t indexOfSectionSymbol(const std::string &section,
        SectionList *sectionList);
};

class ShdrTableContent : public DeferredMap<Section2 *, ElfXX_Shdr> {
public:
    typedef DeferredValueImpl<ElfXX_Shdr> DeferredType;
public:
    DeferredType *add(Section2 *section);
};

class RelocSectionContent : public DeferredMap<address_t, ElfXX_Rela> {
public:
    typedef DeferredValueImpl<ElfXX_Rela> DeferredType;
private:
    SectionRef *outer;
public:
    RelocSectionContent(SectionRef *outer) : outer(outer) {}

    Section2 *getTargetSection();

    DeferredType *add(Chunk *source, Link *link, SymbolTableContent *symtab,
        SectionList *sectionList);
};

#endif
