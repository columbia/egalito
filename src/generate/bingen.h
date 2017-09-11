#ifndef EGALITO_GENERATE_BINGEN_H
#define EGALITO_GENERATE_BINGEN_H

#include <fstream>
#include <vector>
#include "types.h"
#include "chunk/dataregion.h"

class ConductorSetup;
class Module;
class Reloc;
class Symbol;
class Chunk;
class ElfSection;

#if 1
class SymbolMarker {
private:
    Chunk *chunk;
    Symbol *symbol;

public:
    SymbolMarker(Chunk *chunk, Symbol *symbol) : chunk(chunk), symbol(symbol) {}
    Chunk *getChunk() const { return chunk; }
    Symbol *getTargetSymbol() const { return symbol; }
};
#endif

class BinGen {
private:
    ConductorSetup *setup;
    Module *mainModule;
    Module *addon;
    std::vector<Module *> moduleList;
    std::ofstream fs;
    std::vector<SymbolMarker> markerList;
    address_t endOfCode;
    address_t endOfRoData;
    address_t endOfData;
    address_t endOfBss;
public:
    BinGen(ConductorSetup *setup, const char *filename);
    ~BinGen();

    int generate();

private:
    void extractMarkers();
    void applyAdditionalTransform();
    void addCallLogging();
    void addBssClear();
    void dePLT();
    address_t reassignFunctionAddress();
    address_t makeImageBox();
    void changeMapAddress(Module *module, address_t address);
    void interleaveData();
    address_t alignUp(address_t pos, const char *name);
    void fixMarkerSymbols();
    bool fixLinkToSectionEnd(Chunk *chunk, ElfSection *section);
    void resolveLinkerSymbol(Chunk *chunk, address_t address);
    address_t remapData(Module *module, address_t pos, bool writable);
    address_t remapBss(Module *module, address_t pos);
    void writeOut(address_t pos);
    address_t writeOutCode(Module *module, address_t pos);
    address_t writeOutRoData(Module *module, address_t pos);
    address_t writeOutRwData(Module *module, address_t pos);
    address_t writeOutData(Module *module, address_t pos, bool writable);
    address_t getEndOfBss() const;
};

#endif
