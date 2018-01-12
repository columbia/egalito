#ifndef EGALITO_GENERATE_ANYGEN_H
#define EGALITO_GENERATE_ANYGEN_H

#include "section.h"
#include "sectionlist.h"

class Module;
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
    void makeShdrTable();
    void updateOffsets();
private:
    void serialize(const std::string &filename);
};

#endif
