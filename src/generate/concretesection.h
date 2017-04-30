#ifndef EGALITO_GENERATE_CONCRETE_SECTION_H
#define EGALITO_GENERATE_CONCRETE_SECTION_H

#ifndef EGALITO_GENERATE_SECTION_H
    #error "Do not include concretesection.h directly, include section.h"
#endif

#include "deferred.h"

class Function;
class Symbol;

class SymbolTableSection : public Section2 {
public:
    typedef DeferredMap<Symbol *, ElfXX_Sym> ContentType;
public:
    SymbolTableSection(const std::string &name, ElfXX_Word type);
    virtual void init();

    ContentType *getContent()
        { return static_cast<ContentType *>(Section2::getContent()); }

    void add(Function *func, Symbol *sym, size_t strndx);
    void addAtStart(Symbol *symb);
public:
    size_t findIndexWithShIndex(size_t idx);
};

class RelocationSection
    : public SimpleDeferredSection<ConcreteDeferredValue<ElfXX_Rela>> {
private:
    Section *source;
public:
    RelocationSection(Section *source)
        : SimpleDeferredSection<ConcreteDeferredValue<ElfXX_Rela>>(
            ".rela" + source->getName(),
        SHT_RELA, SHF_INFO_LINK), source(source) {}
public:
    Section *getSourceSection() { return source; }
public:
    void addRela(ElfXX_Rela *rela)
        { addValue(rela); }
    virtual Elf64_Shdr *makeShdr(size_t index, size_t nameStrIndex);

    virtual void commitValues();
};

class ShdrTableSection : public DeferredSection<Section, ElfXX_Shdr> {
public:
    using DeferredSection::DeferredSection;
public:
    void addShdrPair(Section *section, ElfXX_Shdr *shdr)
        { addKeyValue(section, shdr); }
};

#endif
