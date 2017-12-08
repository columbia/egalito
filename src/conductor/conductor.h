#ifndef EGALITO_CONDUCTOR_CONDUCTOR_H
#define EGALITO_CONDUCTOR_CONDUCTOR_H

#include "types.h"
#include "chunk/program.h"
#include "chunk/module.h"
#include "chunk/library.h"

class ElfMap;
class Module;
class ChunkVisitor;
class IFuncList;

class Conductor {
private:
    Program *program;
    address_t mainThreadPointer;
    IFuncList *ifuncList;
public:
    Conductor();
    ~Conductor();

    void parseExecutable(ElfMap *elf);
    void parseEgalito(ElfMap *elf);
    void parseLibraries();
    Module *parseAddOnLibrary(ElfMap *elf);
    void parseEgalitoArchive(const char *archive);

    void resolvePLTLinks();
    void resolveTLSLinks();
    void resolveWeak();
    void resolveVTables();
    void setupIFuncLazySelector();
    void fixDataSections();
    void fixPointersInData();

    void writeDebugElf(const char *filename, const char *suffix = "$new");
    void acceptInAllModules(ChunkVisitor *visitor, bool inEgalito = true);

    Program *getProgram() const { return program; }
    LibraryList *getLibraryList() const { return program->getLibraryList(); }

    // deprecated, please use getProgram()->getMain()
    ElfSpace *getMainSpace() const;

    address_t getMainThreadPointer() const { return mainThreadPointer; }
    IFuncList *getIFuncList() const { return ifuncList; }

    void check();
private:
    Module *parse(ElfMap *elf, Library *library);
    void allocateTLSArea();
    void loadTLSData();
};

#endif
