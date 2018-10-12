#ifndef EGALITO_CHUNK_INITFUNCTION_H
#define EGALITO_CHUNK_INITFUNCTION_H

#include "chunk.h"
#include "chunklist.h"
#include "dataregion.h"
#include "archive/chunktypes.h"

class InitFunction : public ChunkSerializerImpl<TYPE_InitFunction,
    AddressableChunkImpl> {
private:
    DataVariable *functionPointer;
public:
    InitFunction(DataVariable *functionPointer) : functionPointer(functionPointer) {}
    
    DataVariable *getFunctionPointer() const { return functionPointer; }
    Link *getLink() const { return functionPointer->getDest(); }
    
    virtual void serialize(ChunkSerializerOperations &op,
        ArchiveStreamWriter &writer);
    virtual bool deserialize(ChunkSerializerOperations &op,
        ArchiveStreamReader &reader);

    virtual void accept(ChunkVisitor *visitor);
};

class InitFunctionList : public ChunkSerializerImpl<TYPE_InitFunctionList,
    CollectionChunkImpl<InitFunction>> {
private:
    bool isInit;  // or fini
public:
    InitFunctionList(bool isInit = true) : isInit(isInit) {}

    bool getIsInit() const { return isInit; }

    virtual void setSize(size_t newSize) {}  // ignored
    virtual void addToSize(diff_t add) {}  // ignored

    virtual void serialize(ChunkSerializerOperations &op,
        ArchiveStreamWriter &writer);
    virtual bool deserialize(ChunkSerializerOperations &op,
        ArchiveStreamReader &reader);

    virtual void accept(ChunkVisitor *visitor);
};

#endif
