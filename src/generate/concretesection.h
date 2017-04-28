#ifndef EGALITO_GENERATE_CONCRETE_SECTION_H
#define EGALITO_GENERATE_CONCRETE_SECTION_H

#ifndef EGALITO_GENERATE_SECTION_H
    #error "Do not include concretesection.h directly, include section.h"
#endif

class Function;
class Symbol;

class SymbolTableSection : public DeferredSection<Symbol, ElfXX_Sym> {
public:
    SymbolTableSection(std::string name, ElfXX_Word type)
        : DeferredSection<Symbol, ElfXX_Sym>(name, type) {}

    using Section::add;
    void add(Function *func, Symbol *sym, size_t nameStrIndex);
    void add(Symbol *symb);

    // we allow both concrete and deferred data here
    virtual size_t getSize() const
        { return Section::getSize() + DeferredSection<Symbol, ElfXX_Sym>::getSize(); }

    virtual ElfXX_Shdr *makeShdr(size_t index, size_t nameStrIndex);

public:
    size_t findIndexWithShIndex(size_t idx);
};

class RelocationSection : public SimpleDeferredSection<ElfXX_Rela> {
private:
    Section *destSection;
    Section *sourceSection;
public:
    RelocationSection(Section *source)
        : SimpleDeferredSection<ElfXX_Rela>(".rela" + source->getName(),
            SHT_RELA, SHF_INFO_LINK), sourceSection(source) {}

public:
    Section *getDestSection() { return destSection; }
    Section *getSourceSection() { return sourceSection; }
    void setDestSection(Section *dest) { destSection = dest; }
public:
    void addRela(ElfXX_Rela *rela)
        { addValue(rela); }
    virtual Elf64_Shdr *makeShdr(size_t index, size_t nameStrIndex);
};

class ShdrTableSection : public DeferredSection<Section, ElfXX_Shdr> {
public:
    using DeferredSection::DeferredSection;
public:
    void addShdrPair(Section *section, ElfXX_Shdr *shdr)
        { addKeyValue(section, shdr); }
};

#endif
