#ifndef EGALITO_CONDUCTOR_CONDUCTOR_H
#define EGALITO_CONDUCTOR_CONDUCTOR_H

#include "elf/sharedlib.h"
#include "elf/elfspace.h"

class ChunkVisitor;

class Conductor {
private:
    LibraryList *libraryList;
    ElfSpaceList *spaceList;
    void *mainThreadPointer;
public:
    Conductor();

    void parseExecutable(ElfMap *elf);
    void parseEgalito(ElfMap *elf, SharedLib *library);
    void parseLibraries();

    void resolvePLTLinks();
    void fixDataSections();
    void fixDataSection(ElfSpace *elfSpace);

    void writeDebugElf(const char *filename, const char *suffix = "$new");
    void acceptInAllModules(ChunkVisitor *visitor, bool inEgalito = true);

    ElfSpace *getMainSpace() const { return spaceList->getMain(); }
    LibraryList *getLibraryList() const { return libraryList; }

    void *getMainThreadPointer() const { return mainThreadPointer; }
private:
    void parse(ElfMap *elf, SharedLib *library);
    void loadTLSData();
};

#endif
