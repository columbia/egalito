#ifndef EGALITO_CHUNK_PROGRAM_H
#define EGALITO_CHUNK_PROGRAM_H

#include "chunk.h"
#include "module.h"

class ElfSpaceList;

class Program : public CollectionChunkImpl<Module> {
private:
    Module *main;
    Module *egalito;
    ElfSpaceList *spaceList;
public:
    Program(ElfSpaceList *spaceList);

    void add(Module *module);
    void addMain(Module *module);
    void addEgalito(Module *module);

    Module *getMain() const { return main; }
    Module *getEgalito() const { return egalito; }

    virtual void accept(ChunkVisitor *visitor);
};

#endif
