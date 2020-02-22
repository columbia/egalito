#ifndef EGALITO_SHELL2_PASSES_H
#define EGALITO_SHELL2_PASSES_H

#include <functional>
#include "code.h"
#include "command.h"
#include "archive/chunktypes.h"
#include "conductor/interface.h"

class ChunkPass;
class Chunk;

class PassContext {
public:
    typedef std::function<ChunkPass* (Chunk *)> GeneratorType;
private:
    bool handled[TYPE_TOTAL];
    GeneratorType generator;
public:
    PassContext() : handled{} {}
    PassContext(std::vector<EgalitoChunkType> types, GeneratorType generator);
    PassContext(bool defaultValue, std::vector<EgalitoChunkType> types,
        GeneratorType generator);

    bool isSupported(Chunk *chunk) const;
    bool isSupported(EgalitoChunkType type) const { return handled[type]; }
    ChunkPass *create(Chunk *chunk) const;
};

class PassCommands {
private:
    FullCommandList *fullList;
    std::map<std::string, PassContext> passMap;
public:
    PassCommands(FullCommandList *fullList) : fullList(fullList) {}
    void construct(EgalitoInterface *egalito);
    std::vector<std::string> getNames() const;
private:
    void makePassMap(EgalitoInterface *egalito);
    bool runPassCommand(EgalitoInterface *egalito, ShellState &state,
        ArgumentValueList &args) const;
    bool listPassesCommand(ShellState &state, ArgumentValueList &args) const;
};

#endif
