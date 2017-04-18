#ifndef EGALITO_ELF_OBJGEN_H
#define EGALITO_ELF_OBJGEN_H
#include "transform/sandbox.h"
#include "elf/elfspace.h"
#include "section.h"

class ObjGen {
private:
    ElfSpace *elfSpace;
    MemoryBacking *backing;
    std::string filename;
private:
    ShdrTableSection *shdrTable;
public:
    ObjGen(ElfSpace *elfSpace, MemoryBacking *backing, std::string filename);
    ~ObjGen() { delete shdrTable; }
public:
    void generate();
private:
    void makeHeader();
    void makeText();
    void makeROData();
    void makeSymbolInfo();
    void serialize();
};

#endif
