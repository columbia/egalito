#ifndef EGALITO_CONDUCTOR_CONDUCTOR_H
#define EGALITO_CONDUCTOR_CONDUCTOR_H

#include <string>
#include "types.h"
#include "chunk/program.h"
#include "chunk/module.h"
#include "chunk/library.h"

class ElfMap;
class Module;
class ChunkVisitor;
class IFuncList;
struct EgalitoTLS;

class Conductor {
private:
    Program *program;
    address_t mainThreadPointer;
    size_t TLSOffsetFromTCB;
    IFuncList *ifuncList;
public:
    Conductor();
    ~Conductor();

    Module *parseExecutable(ElfMap *elf, const std::string &fullPath = "");
    Module *parseEgalito(ElfMap *elf, const std::string &fullPath = "");
    void parseEgalitoElfSpaceOnly(ElfMap *elf, Module *module,
        const std::string &fullPath);
    void parseLibraries();
    Module *parseAddOnLibrary(ElfMap *elf);
    void parseEgalitoArchive(const char *archive);

    void resolvePLTLinks();
    void resolveTLSLinks();
    void resolveData(bool justBridge = false);
    void resolveVTables();
    void setupIFuncLazySelector();
    void fixDataSections(bool allocateTLS = true);
    EgalitoTLS *getEgalitoTLS() const;

    void writeDebugElf(const char *filename, const char *suffix = "$new");
    void acceptInAllModules(ChunkVisitor *visitor, bool inEgalito = true);

    Program *getProgram() const { return program; }
    LibraryList *getLibraryList() const { return program->getLibraryList(); }

    // deprecated, please use getProgram()->getMain()
    ElfSpace *getMainSpace() const;

    address_t getMainThreadPointer() const { return mainThreadPointer; }
    IFuncList *getIFuncList() const { return ifuncList; }

    void loadTLSDataFor(address_t tcb);

    void check();
private:
    Module *parse(ElfMap *elf, Library *library);
    void allocateTLSArea(address_t base);
    void loadTLSData();
    void backupTLSData();
};

#endif
