#ifndef EGALITO_CHUNK_PROGRAM_H
#define EGALITO_CHUNK_PROGRAM_H

#include "chunk.h"
#include "module.h"
#include "archive/chunktypes.h"

class ElfSpaceList;

class Program : public ChunkSerializerImpl<TYPE_Program,
    CollectionChunkImpl<Module>> {
private:
    Module *main;
    Module *egalito;
    ElfSpaceList *spaceList;
    Chunk *entryPoint;
public:
    Program(ElfSpaceList *spaceList = nullptr);

    void add(Module *module);
    void setMain(Module *module);
    void setEgalito(Module *module);

    Module *getMain() const { return main; }
    Module *getEgalito() const { return egalito; }

    void setEntryPoint(Chunk *chunk) { entryPoint = chunk; }
    Chunk *getEntryPoint() const { return entryPoint; }
    address_t getEntryPointAddress();

    virtual void serialize(ChunkSerializerOperations &op,
        ArchiveStreamWriter &writer);
    virtual bool deserialize(ChunkSerializerOperations &op,
        ArchiveStreamReader &reader);

    virtual void accept(ChunkVisitor *visitor);
};

#endif
