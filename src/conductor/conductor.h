#ifndef EGALITO_CONDUCTOR_CONDUCTOR_H
#define EGALITO_CONDUCTOR_CONDUCTOR_H

#include "elf/elfforest.h"

class ChunkVisitor;
class Module;
class IFuncList;

class Conductor {
private:
    ElfForest *forest;
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
    ElfSpace *getMainSpace() const { return forest->getMainSpace(); }
    SharedLibList *getSharedLibList() const { return forest->getLibraryList(); }

    address_t getMainThreadPointer() const { return mainThreadPointer; }
    IFuncList *getIFuncList() const { return ifuncList; }

    void check();
private:
    ElfSpaceList *getSpaceList() const { return forest->getSpaceList(); }
    ElfSpace *parse(ElfMap *elf, SharedLib *library);
    void allocateTLSArea();
    void loadTLSData();
};

#endif
