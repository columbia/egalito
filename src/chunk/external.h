#ifndef EGALITO_CHUNK_EXTERNAL_H
#define EGALITO_CHUNK_EXTERNAL_H

#include <string>
#include "chunk.h"
#include "chunklist.h"
#include "elf/symbol.h"
#include "archive/chunktypes.h"

class Chunk;
class Program;
class Module;

class ExternalSymbol : public ChunkSerializerImpl<TYPE_ExternalSymbol,
    ChunkImpl> {
private:
    std::string name;
    Symbol::SymbolType type;
    Symbol::BindingType bind;
    Chunk *resolved;
    Module *resolvedModule;
public:
    ExternalSymbol() : type(Symbol::TYPE_UNKNOWN), bind(Symbol::BIND_LOCAL) {}
    ExternalSymbol(const std::string &name, Symbol::SymbolType type,
        Symbol::BindingType bind) : name(name), type(type), bind(bind) {}

    std::string getName() const { return name; }
    void setResolved(Chunk *chunk) { this->resolved = chunk; }
    Chunk *getResolved() const { return resolved; }
    void setResolvedModule(Module *module) { resolvedModule = module; }
    Module *getResolvedModule() const { return resolvedModule; }

    Symbol::SymbolType getType() const { return type; }
    Symbol::BindingType getBind() const { return bind; }

    virtual void serialize(ChunkSerializerOperations &op,
        ArchiveStreamWriter &writer);
    virtual bool deserialize(ChunkSerializerOperations &op,
        ArchiveStreamReader &reader);

    virtual void accept(ChunkVisitor *visitor);
};

class ExternalSymbolList : public ChunkSerializerImpl<TYPE_ExternalSymbolList,
    CompositeChunkImpl<ExternalSymbol>> {
public:
    virtual void serialize(ChunkSerializerOperations &op,
        ArchiveStreamWriter &writer);
    virtual bool deserialize(ChunkSerializerOperations &op,
        ArchiveStreamReader &reader);

    virtual void accept(ChunkVisitor *visitor);
};

class ExternalSymbolFactory {
private:
    Module *module;
public:
    ExternalSymbolFactory(Module *module) : module(module) {}

    ExternalSymbol *makeExternalSymbol(Symbol *symbol);
    ExternalSymbol *makeExternalSymbol(const std::string &name,
        Symbol::SymbolType type, Symbol::BindingType bind, Chunk *resolved);

    void resolveAllSymbols(Program *program);
    static void resolveOneSymbol(Program *program, ExternalSymbol *xSymbol);
private:
    ExternalSymbolList *makeExternalSymbolList();
};

#endif
