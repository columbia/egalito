#ifndef EGALITO_CHUNK_CHUNKITER_H
#define EGALITO_CHUNK_CHUNKITER_H

#include "concrete.h"
#include "chunklist.h"

// Note: this file is heavily dependent on internals of chunklist.h.
#ifndef INCLUDE_FROM_CONCRETE_H
    #error "Please do not include chunkiter.h directly. Include concrete.h."
#endif

template <typename BaseType>
class CIterChildren {
private:
    typedef typename BaseType::ChunkChildType ChildType;
    typedef std::vector<ChildType *> ChildListType;
    BaseType *base;
public:
    CIterChildren(BaseType *base) : base(base) {}

    typename ChildListType::iterator begin()
        { return base->getChildren()->getIterable()->iterable().begin(); }
    typename ChildListType::iterator end()
        { return base->getChildren()->getIterable()->iterable().end(); }
};

class CIterFunctions {
private:
    Module *module;
public:
    CIterFunctions(Module *module) : module(module) {}

    std::vector<Function *>::iterator begin()
        { return module->getFunctionList()->getChildren()->getIterable()->iterable().begin(); }
};

class CIter {
public:
    template <typename BaseType>
    static CIterChildren<BaseType> children(BaseType *base)
        { return CIterChildren<BaseType>(base); }

    template <typename BaseType>
    static typename BaseType::ChunkChildType *findChild(BaseType *base, const char *name)
        { return base->getChildren()->getNamed()->find(name); }

    template <typename BaseType>
    static IterableChunkList<typename BaseType::ChunkChildType> *
        iterable(BaseType *base) { return base->getChildren()->getIterable(); }
    template <typename BaseType>
    static NamedChunkList<typename BaseType::ChunkChildType> *
        named(BaseType *base) { return base->getChildren()->getNamed(); }
    template <typename BaseType>
    static SpatialChunkList<typename BaseType::ChunkChildType> *
        spatial(BaseType *base) { return base->getChildren()->getSpatial(); }

    static CIterChildren<FunctionList> functions(Module *module)
        { return CIterChildren<FunctionList>(module->getFunctionList()); }
    static CIterChildren<PLTList> plts(Module *module)
        { return CIterChildren<PLTList>(module->getPLTList()); }
    static CIterChildren<DataRegionList> regions(Module *module)
        { return CIterChildren<DataRegionList>(module->getDataRegionList()); }

    static CIterChildren<Program> modules(Program *program)
        { return CIterChildren<Program>(program); }
    static CIterChildren<LibraryList> libraries(Program *program)
        { return CIterChildren<LibraryList>(program->getLibraryList()); }
};

#endif
