#ifndef EGALITO_CHUNK_INITFUNCTION_H
#define EGALITO_CHUNK_INITFUNCTION_H

#include "chunk.h"
#include "chunklist.h"
#include "dataregion.h"
#include "function.h"
#include "archive/chunktypes.h"

class InitFunction : public ChunkSerializerImpl<TYPE_InitFunction,
    AddressableChunkImpl> {
private:
    bool init;  // or fini
    bool specialCase;
    Function *function;
    DataVariable *dataVariable;  // may be null
public:
    // ensure that dataVariable->getDest()->getTarget() exists before calling this
    InitFunction(bool init, DataVariable *dataVariable);
    InitFunction(bool init, Function *function, bool specialCase = false)
        : init(init), specialCase(specialCase), function(function),
        dataVariable(nullptr) {}

    bool isInit() const { return init; }
    bool isSpecialCase() const { return specialCase; }

    DataVariable *getDataVariable() const { return dataVariable; }
    Link *getLink() const { return dataVariable ? dataVariable->getDest() : nullptr; }
    Function *getFunction() const { return function; }
    virtual std::string getName() const { return function->getName(); }

    virtual void serialize(ChunkSerializerOperations &op,
        ArchiveStreamWriter &writer);
    virtual bool deserialize(ChunkSerializerOperations &op,
        ArchiveStreamReader &reader);

    virtual void accept(ChunkVisitor *visitor);
};

class InitFunctionList : public ChunkSerializerImpl<TYPE_InitFunctionList,
    CollectionChunkImpl<InitFunction>> {
private:
    bool init;  // or fini
    InitFunction *specialCase;  // referred to by .init or .fini section
public:
    InitFunctionList(bool init = true)
        : init(init), specialCase(nullptr) {}

    bool isInit() const { return init; }

    void setSpecialCase(InitFunction *f) { specialCase = f; }
    InitFunction *getSpecialCase() const { return specialCase; }

    virtual void setSize(size_t newSize) {}  // ignored
    virtual void addToSize(diff_t add) {}  // ignored

    virtual void serialize(ChunkSerializerOperations &op,
        ArchiveStreamWriter &writer);
    virtual bool deserialize(ChunkSerializerOperations &op,
        ArchiveStreamReader &reader);

    virtual std::string getName() const;
    virtual void accept(ChunkVisitor *visitor);
};

#endif
