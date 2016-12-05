#ifndef EGALITO_CHUNK_CONCRETE_H
#define EGALITO_CHUNK_CONCRETE_H

#include "chunk.h"
#include "chunklist.h"
#include "instruction.h"

class Program;
class CodePage;
class Function;
class Block;
class Instruction;

class ChunkVisitor {
public:
    virtual ~ChunkVisitor() {}
    virtual void visit(Program *program) = 0;
    virtual void visit(CodePage *codePage) = 0;
    virtual void visit(Function *function) = 0;
    virtual void visit(Block *block) = 0;
    virtual void visit(Instruction *instruction) = 0;
};
class ChunkListener {
public:
    virtual void visit(Program *program) {}
    virtual void visit(CodePage *codePage) {}
    virtual void visit(Function *function) {}
    virtual void visit(Block *block) {}
    virtual void visit(Instruction *instruction) {}
};

class Program : public ChunkImpl {
public:
    virtual void accept(ChunkVisitor *visitor) { visitor->visit(this); }
};
class CodePage : public XRefDecorator<CompositeChunkImpl<Block>> {
public:
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

class ChunkFactory {
public:
    Program *makeProgram();
    CodePage *makeCodePage();
    Function *makeFunction(Symbol *symbol);
    Block *makeBlock();
    Instruction *makeInstruction(InstructionSemantic *semantic);
};

#endif
