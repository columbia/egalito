#ifndef EGALITO_CHUNK_EXTERNAL_H
#define EGALITO_CHUNK_EXTERNAL_H

#include <string>
#include <vector>
#include "chunk.h"
#include "elf/symbol.h"

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
    ExternalSymbol(const std::string &name, Symbol::SymbolType type,
        Symbol::BindingType bind) : name(name), type(type), bind(bind) {}

    const std::string &getName() const { return name; }
    void setResolved(Chunk *chunk) { this->resolved = chunk; }
    Chunk *getResolved() const { return resolved; }
    void setResolvedModule(Module *module) { resolvedModule = module; }
    Module *getResolvedModule() const { return resolvedModule; }

    Symbol::SymbolType getType() const { return type; }
    Symbol::BindingType getBind() const { return bind; }
};

class ExternalSymbolList : public ChunkSerializeImpl<TYPE_ExternalSymbolList,
    CompositeChunkImpl<ExternalSymbol>> {
public:
    void addExternalSymbol(ExternalSymbol *xSymbol)
        { externalSymbols.push_back(xSymbol); }
};

class ExternalSymbolFactory {
private:
    Module *module;
public:
    ExternalFactory(Module *module) : module(module) {}

    ExternalSymbol *makeExternalSymbol(Symbol *symbol);
    ExternalSymbol *makeExternalSymbol(const std::string &name,
        Symbol::SymbolType type, Symbol::BindingType bind, Chunk *resolved);

    void resolveAllSymbols(Program *program);
private:
    ExternalData *makeExternalSymbolList();
    void resolveOneSymbol(Program *program, ExternalSymbol *xSymbol);
};

#endif
