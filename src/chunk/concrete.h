#ifndef EGALITO_CHUNK_CONCRETE_H
#define EGALITO_CHUNK_CONCRETE_H

#include "chunk.h"
#include "chunklist.h"
#include "instruction.h"

class Program;
class Module;
class FunctionList;
class BlockSoup;
class PLTList;
class Function;
class Block;
class Instruction;
class PLTTrampoline;
class TLSList;

class ChunkVisitor {
public:
    virtual ~ChunkVisitor() {}
    virtual void visit(Program *program) = 0;
    virtual void visit(Module *function) = 0;
    virtual void visit(FunctionList *functionList) = 0;
    virtual void visit(BlockSoup *functionList) = 0;
    virtual void visit(PLTList *functionList) = 0;
    virtual void visit(Function *function) = 0;
    virtual void visit(Block *block) = 0;
    virtual void visit(Instruction *instruction) = 0;
    virtual void visit(PLTTrampoline *instruction) = 0;
};
class ChunkListener {
public:
    virtual void visit(Program *program) {}
    virtual void visit(Module *function) {}
    virtual void visit(FunctionList *functionList) {}
    virtual void visit(BlockSoup *functionList) {}
    virtual void visit(PLTList *functionList) {}
    virtual void visit(Function *function) {}
    virtual void visit(Block *block) {}
    virtual void visit(Instruction *instruction) {}
    virtual void visit(PLTTrampoline *instruction) {}
};

class Program : public ChunkImpl {
public:
    virtual void accept(ChunkVisitor *visitor) { visitor->visit(this); }
};
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

    virtual void accept(ChunkVisitor *visitor) { visitor->visit(this); }
};
class FunctionList : public CompositeChunkImpl<Function> {
public:
    virtual void setSize(size_t newSize) {}  // ignored
    virtual void addToSize(diff_t add) {}  // ignored
    virtual void accept(ChunkVisitor *visitor) { visitor->visit(this); }
};
class BlockSoup : public CompositeChunkImpl<Block> {
public:
    virtual void setSize(size_t newSize) {}  // ignored
    virtual void addToSize(diff_t add) {}  // ignored
    virtual void accept(ChunkVisitor *visitor) { visitor->visit(this); }
};
class PLTList : public CompositeChunkImpl<PLTTrampoline> {
public:
    virtual void setSize(size_t newSize) {}  // ignored
    virtual void addToSize(diff_t add) {}  // ignored
    virtual void accept(ChunkVisitor *visitor) { visitor->visit(this); }
};

class Symbol;
class Function : public CompositeChunkImpl<Block> {
private:
    Symbol *symbol;
public:
    Function(Symbol *symbol) : symbol(symbol) {}

    Symbol *getSymbol() const { return symbol; }
    std::string getName() const { return symbol->getName(); }

    virtual void accept(ChunkVisitor *visitor) { visitor->visit(this); }
};
class Block : public CompositeChunkImpl<Instruction> {
public:
    virtual std::string getName() const;

    virtual void accept(ChunkVisitor *visitor) { visitor->visit(this); }
};
class InstructionSemantic;
class SemanticVisitor;
class Instruction : public ChunkImpl {
private:
    InstructionSemantic *semantic;
public:
    Instruction(InstructionSemantic *semantic = nullptr)
        : semantic(semantic) {}

    virtual std::string getName() const;

    InstructionSemantic *getSemantic() const { return semantic; }
    void setSemantic(InstructionSemantic *semantic)
        { this->semantic = semantic; }

    virtual size_t getSize() const { return semantic->getSize(); }
    virtual void setSize(size_t value) { semantic->setSize(value); }

    virtual void accept(ChunkVisitor *visitor) { visitor->visit(this); }
};

// PLTTrampoline defined in plt.h
#include "plt.h"

#define INCLUDE_FROM_CONCRETE_H
#include "chunkiter.h"
#undef INCLUDE_FROM_CONCRETE_H

#endif
