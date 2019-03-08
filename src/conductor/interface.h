#ifndef EGALITO_CONDUCTOR_INTERFACE_H
#define EGALITO_CONDUCTOR_INTERFACE_H

#include <string>

#include "setup.h"
#include "conductor.h"
#include "chunk/program.h"
#include "chunk/module.h"
#include "chunk/dump.h"

class EgalitoInterface {
private:
    ConductorSetup setup;
public:
    EgalitoInterface(bool verboseLogging = true, bool useLoggingEnvVar = true);
    bool parseLoggingEnvVar(const char *envVar = "EGALITO_DEBUG");
    void muteOutput();
    bool setLogLevel(const char *logname, int level);

    void initializeParsing();
    Module *parse(const std::string &filename, bool recursiveDependencies = false);
    Module *parse(const std::string &filename, Library::Role role,
        bool recursiveDependencies = false);
    void parseRecursiveDependencies();

    Program *getProgram() const { return setup.getConductor()->getProgram(); }
    LibraryList *getLibraryList() const { return getProgram()->getLibraryList(); }
    ConductorSetup *getSetup() { return &setup; }
    Conductor *getConductor() const { return setup.getConductor(); }

    template <typename ChunkType>
    void dump(ChunkType *chunk);

    void generate(const std::string &outputName);
    void generate(const std::string &outputName, bool isUnion);
public:
    void prepareForGeneration(bool isUnion);
    void assignNewFunctionAddresses();
};

template <typename ChunkType>
void EgalitoInterface::dump(ChunkType *chunk) {
    ChunkDumper dump;
    chunk->accept(&dump);
}

#endif
