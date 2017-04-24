#ifndef EGALITO_GENERATE_CONCRETE_SECTION_H
#define EGALITO_GENERATE_CONCRETE_SECTION_H

#ifndef EGALITO_GENERATE_SECTION_H
    #error "Do not include concretesection.h directly, include section.h"
#endif

class Function;
class Symbol;

class SymbolTableSection : public DeferredContentSection<Symbol, ElfXX_Sym> {
public:
    SymbolTableSection(std::string name, ElfXX_Word type)
        : DeferredContentSection<Symbol, ElfXX_Sym>(name, type) {}

    using Section::add;
    void add(Function *func, Symbol *sym, size_t nameStrIndex);
    void add(ElfXX_Sym symbol);

    // we allow both concrete and deferred data here
    virtual size_t getSize() const
        { return Section::getSize() + DeferredContentSection<Symbol, ElfXX_Sym>::getSize(); }

    virtual ElfXX_Shdr *makeShdr(size_t index, size_t nameStrIndex);

public:
    size_t findIndexWithShIndex(size_t idx);
};

class RelocationSection : public PtrDeferredContentSection<Section, ElfXX_Rela> {
private:
    Section *targetSection;
public:
    using PtrDeferredContentSection::PtrDeferredContentSection;

    void setTargetSection(Section *target) { targetSection = target; }
    void addRelaPair(Section *section, ElfXX_Rela *rela)
        { addElement(section, rela); }
    virtual Elf64_Shdr *makeShdr(size_t index, size_t nameStrIndex);
};

class ShdrTableSection : public PtrDeferredContentSection<Section, ElfXX_Shdr> {
public:
    using PtrDeferredContentSection::PtrDeferredContentSection;
public:
    void addShdrPair(Section *section, ElfXX_Shdr *shdr)
        { addElement(section, shdr); }
};

#endif
