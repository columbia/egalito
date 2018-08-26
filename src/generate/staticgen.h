#ifndef EGALITO_GENERATE_STATICGEN_H
#define EGALITO_GENERATE_STATICGEN_H

#include <string>
#include "types.h"
#include "section.h"
#include "sectionlist.h"

class Program;
class Module;
class Function;
class MemoryBufferBacking;

class StaticGen {
private:
    Program *program;
    MemoryBufferBacking *backing;
    SectionList sectionList;
public:
    StaticGen(Program *program, MemoryBufferBacking *backing);

    void generate(const std::string &filename);
private:
    void makeHeader();
    void makeSymtabSection();
    void makeSectionSymbols();
    void makeShdrTable();
    void makePhdrTable();
    void makeTextMapping();
    void makeDynamicSection();
    void makePhdrLoadSegment();
    void makeInitArraySections();
    void makeInitArraySectionLinks();
private:
    void updateOffsets();
    void serialize(const std::string &filename);
private:
    size_t shdrIndexOf(Section *section);
    size_t shdrIndexOf(const std::string &name);
    static bool blacklistedSymbol(const std::string &name);
};

#endif
