#ifndef EGALITO_ELF_OBJGEN_H
#define EGALITO_ELF_OBJGEN_H
#include "transform/sandbox.h"
#include "elf/elfspace.h"
#include "section.h"

class ObjGen {
private:
    class Sections {
    private:
        std::map<std::string, Section *> sectionMap;
        std::vector<Section *> sections;
        Section *text;
    public:
        Sections();
        ~Sections();
    public:
        void addSection(Section *section)
            { sectionMap[section->getName()] = section; sections.push_back(section); }
        std::vector<Section *>::iterator begin() { return sections.begin(); }
        std::vector<Section *>::iterator end() { return sections.end(); }
        Section *operator [](std::string name) {return sectionMap[name];}
    public:
        Section *getText() { return text; }
        void addTextSection(Section *s) { addSection(s); text = s; }
    };
private:
    ElfSpace *elfSpace;
    MemoryBacking *backing;
    std::string filename;
private:
    Sections sections;
public:
    ObjGen(ElfSpace *elfSpace, MemoryBacking *backing, std::string filename);
public:
    void generate();
private:
    void makeHeader();
    void makeText();
    void makeSymbolInfo();
    void makeRoData();
    void makeShdrTable();
private:
    void updateSymbolTable();
    void updateRelocations();
    void updateOffsetAndAddress();
    void updateShdrTable();
    void updateHeader();
    void serialize();
};

#endif
