#ifndef EGALITO_CHUNK_MODULE_H
#define EGALITO_CHUNK_MODULE_H

#include "chunk.h"
#include "chunklist.h"

class ElfSpace;
class FunctionList;
class BlockSoup;
class PLTList;
class TLSList;

class Module : public CompositeChunkImpl<Chunk> {
private:
    ElfSpace *elfSpace;
private:
    FunctionList *functionList;
    BlockSoup *blockSoup;
    PLTList *pltList;
    TLSList *tlsList;
public:
    Module() : elfSpace(nullptr), functionList(nullptr), blockSoup(nullptr),
        pltList(nullptr), tlsList(nullptr) {}

    std::string getName() const;

    void setElfSpace(ElfSpace *space) { elfSpace = space; }
    ElfSpace *getElfSpace() const { return elfSpace; }

    FunctionList *getFunctionList() const { return functionList; }
    BlockSoup *getBlockSoup() const { return blockSoup; }
    PLTList *getPLTList() const { return pltList; }
    TLSList *getTLSList() const { return tlsList; }

    void setFunctionList(FunctionList *list) { functionList = list; }
    void setBlockSoup(BlockSoup *soup) { blockSoup = soup; }
    void setPLTList(PLTList *list) { pltList = list; }
    void setTLSList(TLSList *list) { tlsList = list; }

    virtual void setSize(size_t newSize) {}  // ignored
    virtual void addToSize(diff_t add) {}  // ignored

    virtual void accept(ChunkVisitor *visitor);
};

#endif
