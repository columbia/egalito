#ifndef EGALITO_CHUNK_EXTERNAL_H
#define EGALITO_CHUNK_EXTERNAL_H

#include <string>
#include <vector>
#include "elf/symbol.h"
#include "module.h"
#include "function.h"

class Program;

class ExternalChunk {
public:
    virtual ~ExternalChunk() {}

    virtual Chunk *getResolved() const = 0;
};

class ExternalModule : public ExternalChunk {
private:
    std::string name;
    Module *resolved;
    std::string resolvedPath;
public:
    ExternalModule(const std::string &name) : name(name), resolved(nullptr) {}

    const std::string &getName() const { return name; }
    void setResolved(Module *module) { this->resolved = module; }
    Module *getResolved() const { return resolved; }
    void setResolvedPath(const std::string &path) { resolvedPath = path; }
    const std::string getResolvedPath() const { return resolvedPath; }
};

class ExternalSymbol : public ExternalChunk {
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

class ExternalData {
private:
    std::string originalElfName;
    std::vector<std::string> searchPaths;
    std::vector<ExternalModule *> externalModules;
    std::vector<ExternalSymbol *> externalSymbols;
public:
    const std::string &getOriginalElfName() const { return originalElfName; }
    void setOriginalElfName(const std::string &name)
        { originalElfName = name; }

    const std::vector<std::string> &getSearchPaths() const
        { return searchPaths; }

    void registerModule(Module *module);
    std::vector<ExternalModule *> &getExternalModules()
        { return externalModules; }
    void resolveAllSymbols(Program *program);
private:
    void resolveOneSymbol(Program *program, ExternalSymbol *xSymbol);
};

#endif
