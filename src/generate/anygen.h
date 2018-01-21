#ifndef EGALITO_GENERATE_ANYGEN_H
#define EGALITO_GENERATE_ANYGEN_H

#include <string>
#include "types.h"
#include "section.h"
#include "sectionlist.h"

class Module;
class Function;
class MemoryBacking;

class AnyGen {
private:
    Module *module;
    MemoryBacking *backing;
    SectionList sectionList;
public:
    AnyGen(Module *module, MemoryBacking *backing);

    void generate(const std::string &filename);
private:
    void makeHeader();
    void makeSymtabSection();
    void makeSectionSymbols();
    void makeShdrTable();
    void makePhdrTable();

    void makeDataSections();

    void makeText();
    void makeRelocSectionFor(const std::string &otherName);
    void makeSymbolsAndRelocs(address_t begin, size_t size,
        const std::string &textSection);
    void makeSymbolInText(Function *func, const std::string &textSection);
    void makeRelocInText(Function *func, const std::string &textSection);

    void makePaddingSection(size_t desiredAlignment);
private:
    void updateOffsets();
    void serialize(const std::string &filename);
private:
    size_t shdrIndexOf(Section *section);
    size_t shdrIndexOf(const std::string &name);
    static bool blacklistedSymbol(const std::string &name);
};

#endif
