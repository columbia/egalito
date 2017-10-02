#ifndef EGALITO_CHUNK_PROGRAM_H
#define EGALITO_CHUNK_PROGRAM_H

#include "chunk.h"
#include "module.h"
#include "archive/archive.h"

class ElfSpaceList;

class Program : public ChunkSerializerImpl<CollectionChunkImpl<Module>, EgalitoArchive::TYPE_Program> {
private:
    Module *main;
    Module *egalito;
    ElfSpaceList *spaceList;
public:
    Program(ElfSpaceList *spaceList);

    void add(Module *module);
    void setMain(Module *module);
    void setEgalito(Module *module);

    Module *getMain() const { return main; }
    Module *getEgalito() const { return egalito; }

    virtual void serialize(ChunkSerializerOperations &op,
        ArchiveStreamWriter &writer);
    virtual bool deserialize(ChunkSerializerOperations &op,
        ArchiveStreamReader &reader);

    virtual void accept(ChunkVisitor *visitor);
};

#endif
