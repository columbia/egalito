#ifndef EGALITO_ELF_OBJGEN_H
#define EGALITO_ELF_OBJGEN_H
#include "transform/sandbox.h"
#include "elf/elfspace.h"
#include "section.h"

class ObjGen {
private:
    class Sections {
    private:
        std::vector<Section *> sections;
        Section *header;
        Section *strtab;
        Section *shstrtab;
        Section *text;
    public:
        Sections();
        ~Sections();
    public:
        void addSection(Section *section) { sections.push_back(section); }
        std::vector<Section *> getSections() { return sections; }
        Section *findSection(const std::string &name);
    public:
        Section *getHeader() { return header; }
        Section *getStrTab() { return strtab; }
        Section *getShStrTab() { return shstrtab; }
        Section *getText() { return text; }
        void addTextSection(Section *s) { addSection(s); text = s; }
    };
private:
    ElfSpace *elfSpace;
    MemoryBacking *backing;
    std::string filename;
private:
    Sections *sections;
public:
    ObjGen(ElfSpace *elfSpace, MemoryBacking *backing, std::string filename);
    ~ObjGen() { delete sections; }
public:
    void generate();
private:
    void makeHeader();
    void makeText();
    void makeROData();
    void makeSymbolInfo();
    void makeShdrTable();
private:
    void updateOffsetAndAddress();
    void updateSymbolTable();
    void updateShdrTable();
    void updateHeader();
    void serialize();
};

#endif
