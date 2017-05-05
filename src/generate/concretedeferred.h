#ifndef EGALITO_GENERATE_CONCRETE_DEFERRED_H
#define EGALITO_GENERATE_CONCRETE_DEFERRED_H

#include <vector>
#include "deferred.h"
#include "chunk/link.h"
#include "elf/elfxx.h"

class Section;
class SectionRef;
class Symbol;
class Function;
class Instruction;
class ElfSpace;
class Chunk;
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

class ShdrTableContent : public DeferredMap<Section *, ElfXX_Shdr> {
public:
    typedef DeferredValueImpl<ElfXX_Shdr> DeferredType;
public:
    DeferredType *add(Section *section);
};

class RelocSectionContent : public DeferredMap<address_t, ElfXX_Rela> {
public:
    typedef DeferredValueImpl<ElfXX_Rela> DeferredType;
private:
    SectionRef *outer;
    SectionList *sectionList;
    ElfSpace *elfSpace;
public:
    RelocSectionContent(SectionRef *outer, SectionList *sectionList,
        ElfSpace *elfSpace) : outer(outer), sectionList(sectionList),
        elfSpace(elfSpace) {}

    Section *getTargetSection();

    DeferredType *add(Chunk *source, Link *link);
private:
    DeferredType *makeDeferredForLink(Instruction *source);
    DeferredType *addConcrete(Instruction *source, DataOffsetLink *link);
    DeferredType *addConcrete(Instruction *source, PLTLink *link);
    DeferredType *addConcrete(Instruction *source, SymbolOnlyLink *link);
};

#endif
