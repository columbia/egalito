#include "chunk/disassemble.h"
#include "elfbuilder.h"

void ElfBuilder::buildChunkList() {
    SymbolList *symbolList = elfSpace->getSymbolList();
    if(symbolList == nullptr)
        throw "ElfMap or Symbol List not set";

    ChunkList<Function> functionList;
    auto baseAddr = elfSpace->getElfMap()->getCopyBaseAddress();
    for(auto sym : *symbolList) {
        Function *function = Disassemble::function(sym, baseAddr, symbolList);
        functionList.add(function);
    }
    elfSpace->setChunkList(&functionList);
}

void ElfBuilder::buildSymbols() {
    if(elfSpace->getElfMap() == nullptr)
        throw "ElfMap not set";

    SymbolList symbolList = SymbolList::buildSymbolList(elfSpace->getElfMap());
    elfSpace->setSymbolList(&symbolList);
}

void ElfBuilder::buildRelocList() {
    if(elfSpace->getElfMap() == nullptr || elfSpace->getSymbolList() == nullptr)
        throw "ElfMap not set";

    RelocList relocList = RelocList::buildRelocList(elfSpace->getElfMap(), elfSpace->getSymbolList());
    elfSpace->setRelocList(&relocList);
}

void ElfBuilder::copyCodeToSandbox() {
    ChunkList<Function> *chunkList = elfSpace->getChunkList();
    if(sandbox == nullptr || chunkList == nullptr)
      throw "Sandbox, elfspace, or chunklist not set";

    for(auto chunk : *chunkList) {
        auto slot = sandbox->allocate(chunk->getSize());
        chunk->setAddress(slot.getAddress());
    }
}
