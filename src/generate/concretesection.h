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
    typedef DeferredMap<Symbol *, ElfXX_Sym *> ContentType;
public:
    SymbolTableSection(const std::string &name, ElfXX_Word type);

    ContentType *getContent()
        { return static_cast<ContentType *>(Section2::getContent()); }

    DeferredValueImpl<ElfXX_Sym *> *add(Function *func, Symbol *sym, size_t strndx);
    void addAtStart(Symbol *symb);
public:
    size_t findIndexWithShIndex(size_t idx);
};

class RelocationSection : public Section2 {
public:
    typedef DeferredList<ElfXX_Rela *> ContentType;
private:
    Section2 *source;
public:
    RelocationSection(Section2 *source);

    ContentType *getContent()
        { return static_cast<ContentType *>(Section2::getContent()); }

    Section2 *getSourceSection() { return source; }

    void add(const ContentType::ValueType &rela) { getContent()->add(rela); }
    virtual Elf64_Shdr *makeShdr(size_t index, size_t nameStrIndex);

    virtual void commitValues();
};

class ShdrTableSection : public Section2 {
public:
    typedef DeferredMap<Section2 *, ElfXX_Shdr *> ContentType;
public:
    using Section2::Section2;

    ContentType *getContent()
        { return static_cast<ContentType *>(Section2::getContent()); }

    void add(Section2 *section, ContentType::ValueType shdr)
        { getContent()->add(section, shdr); }
};

#endif
