#ifndef EGALITO_GENERATE_ANYGEN_H
#define EGALITO_GENERATE_ANYGEN_H

#include <string>
#include "types.h"
#include "section.h"
#include "sectionlist.h"

class Module;
class Function;
class MemoryBufferBacking;

class AnyGen {
private:
    Module *module;
    MemoryBufferBacking *backing;
    SectionList sectionList;
public:
    AnyGen(Module *module, MemoryBufferBacking *backing);

    void generate(const std::string &filename);
private:
    void makeHeader();
    void makeSymtabSection();
    void makeSectionSymbols();
    void makeShdrTable();
    void makePhdrTable();
private:
    void updateOffsets();
    void serialize(const std::string &filename);
private:
    size_t shdrIndexOf(Section *section);
    size_t shdrIndexOf(const std::string &name);
};

#endif
