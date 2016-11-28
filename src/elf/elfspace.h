#ifndef EGALITO_ELF_ELFSPACE_H
#define EGALITO_ELF_ELFSPACE_H
#include "elfmap.h"
#include "chunk/concrete.h"
#include "chunk/chunklist.h"
#include "reloc.h"
#include "symbol.h"

class ElfSpace {
private:
    ElfMap *elfMap;
    ElfChunkList<Function> *chunkList; // Replace with code tree?
    SymbolList *symbolList;
    RelocList *relocList;
public:
    ElfSpace()
      : elfMap(nullptr), chunkList(nullptr), symbolList(nullptr) {}
public:
    ElfMap *getElfMap() const { return elfMap; }
    ElfChunkList<Function> *getChunkList() const { return chunkList; }
    SymbolList *getSymbolList() const { return symbolList; }
    RelocList *getRelocList() const { return relocList; }
public:
    void setElfMap(ElfMap *map) { elfMap = map; }
    void setChunkList(ElfChunkList<Function> *list) { chunkList = list; }
    void setSymbolList(SymbolList *list) { symbolList = list; }
    void setRelocList(RelocList *list) {relocList = list;}
};
#endif
