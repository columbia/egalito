#ifndef EGALITO_CONDUCTOR_CONDUCTOR_H
#define EGALITO_CONDUCTOR_CONDUCTOR_H

#include "elf/elfforest.h"

class ChunkVisitor;

class Conductor {
private:
    ElfForest *forest;
    Program *program;
    address_t mainThreadPointer;
public:
    Conductor();
    ~Conductor();

    void parseExecutable(ElfMap *elf);
    void parseEgalito(ElfMap *elf, SharedLib *library);
    void parseLibraries();

    void resolvePLTLinks();
    void fixDataSections();
    void fixDataSection(Module *module);

    void writeDebugElf(const char *filename, const char *suffix = "$new");
    void acceptInAllModules(ChunkVisitor *visitor, bool inEgalito = true);

    Program *getProgram() const { return program; }
    ElfSpace *getMainSpace() const { return forest->getMainSpace(); }
    LibraryList *getLibraryList() const { return forest->getLibraryList(); }
    ElfSpaceList *getSpaceList() const { return forest->getSpaceList(); }

    address_t getMainThreadPointer() const { return mainThreadPointer; }
private:
    void parse(ElfMap *elf, SharedLib *library);
    void loadTLSData();
};

#endif
