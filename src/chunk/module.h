#ifndef EGALITO_CHUNK_MODULE_H
#define EGALITO_CHUNK_MODULE_H

#include "chunk.h"
#include "chunklist.h"

class FunctionList;
class BlockSoup;
class PLTList;
class TLSList;

class Module : public CompositeChunkImpl<Chunk> {
private:
    FunctionList *functionList;
    BlockSoup *blockSoup;
    PLTList *pltList;
    TLSList *tlsList;
public:
    Module() : functionList(nullptr), blockSoup(nullptr), pltList(nullptr),
        tlsList(nullptr) {}

    std::string getName() const;

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
