#ifndef EGALITO_ELF_OBJGEN_H
#define EGALITO_ELF_OBJGEN_H

#include "transform/sandbox.h"
#include "elf/elfspace.h"
#include "section.h"
#include "sectionlist.h"

class ObjGen {
private:
    ElfSpace *elfSpace;
    MemoryBacking *backing;
    std::string filename;
    SectionList sectionList;
public:
    ObjGen(ElfSpace *elfSpace, MemoryBacking *backing, std::string filename);
public:
    void generate();
private:
    void makeHeader();
    void makeSymbolInfo();
    void makeText();
    void makeSymbolInfoForText(address_t begin, size_t size,
        const std::string &textSection);
    void makeRoData();
    void makeShdrTable();
private:
    void updateSymbolTable();
    //void updateRelocations();
    void updateOffsetAndAddress();
    //void updateShdrTable();
    void serialize();
private:
    bool blacklistedSymbol(const std::string &name);
};

#endif
