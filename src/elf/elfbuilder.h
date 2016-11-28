#ifndef EGALITO_ELF_ELFBUILDER_H
#define EGALITO_ELF_ELFBUILDER_H
#include "transform/sandbox.h"
#include "elfspace.h"

class ElfBuilder {
private:
    Sandbox *sandbox;
    ElfSpace *elfSpace;
public:
    ElfBuilder(ElfSpace *elfSpace)
        : sandbox(nullptr), elfSpace(elfSpace){}
public:
    void buildSymbolList();
    void buildChunkList();
    void buildRelocList();
    void copyCodeToSandbox();
    void setElfMap(ElfMap *map)
        { elfSpace->setElfMap(map); }
    void setSandbox(Sandbox *box)
        { sandbox = box; }
public:
    ElfSpace *getElfSpace() const { return elfSpace; }
    Sandbox *getSandBox() const { return sandbox; }
    ElfChunkList<Function> *getChunkList() const { return elfSpace->getChunkList(); }
    SymbolList *getSymbolList() const { return elfSpace->getSymbolList(); }
    RelocList *getRelocList() const { return elfSpace->getRelocList(); }
};

#endif
