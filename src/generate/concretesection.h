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

    // we allow both concrete and deferred data here
    virtual size_t getSize() const
        { return Section::getSize() + DeferredContentSection<Symbol, ElfXX_Sym>::getSize(); }

    virtual ElfXX_Shdr *makeShdr(size_t index, size_t nameStrIndex);
};

class RelocationSection : public Section {
private:
    Section *targetSection;
public:
    using Section::Section;

    void setTargetSection(Section *target) { targetSection = target; }

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
