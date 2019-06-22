#ifndef EGALITO_ELF_OBJGEN_H
#define EGALITO_ELF_OBJGEN_H

#include "transform/sandbox.h"
#include "exefile/exefile.h"
#include "chunk/module.h"
#include "chunk/function.h"
#include "section.h"
#include "sectionlist.h"

class ObjGen {
private:
    Module *module;
    ElfExeFile *elfFile;
    MemoryBacking *backing;
    std::string filename;
    SectionList sectionList;
    int sectionSymbolCount;
public:
    ObjGen(Module *module, MemoryBacking *backing, std::string filename);
public:
    void generate();
private:
    void makeHeader();
    void makeSymbolInfo();
    void makeRelocInfo(const std::string &textSection);
    void makeText();
    void makeSymbolsAndRelocs(address_t begin, size_t size,
        const std::string &textSection);
    void makeSymbolInText(Function *func, const std::string &textSection);
    void makeRelocInText(Function *func, const std::string &textSection);
    void makeRoData();
    void makeShdrTable();
private:
    void updateSymbolTable();
    void updateOffsets();
    void serialize();
private:
    static bool blacklistedSymbol(const std::string &name);
};

#endif
