#ifndef EGALITO_CONDUCTOR_INTERFACE_H
#define EGALITO_CONDUCTOR_INTERFACE_H

#include <string>

#include "setup.h"
#include "conductor.h"
#include "chunk/program.h"
#include "chunk/module.h"
#include "chunk/dump.h"

/** Highest-level generic interface for using Egalito. Parses ELF files,
    producing a Chunk heirarchy rooted in getProgram(); provides access to
    essential classes for transformations; and generates mirrorgen/uniongen
    ELF outputs. If more sophisticated functionality is required, simply
    access the ConductorSetup or Conductor.
*/
class EgalitoInterface {
private:
    ConductorSetup setup;
public:
    /** Creates an EgalitoInterface. One EgalitoInterface can be reused,
        or multiple instances can be created (sequentially). Default arguments
        cause debugging info to be logged and EGALITO_DEBUG to be honoured. To
        control logging levels at runtime, try TemporaryLogLevel.
    */
    EgalitoInterface(bool verboseLogging = true, bool useLoggingEnvVar = true);

    /** Creates Program. Call this before any invocation of parse(), and may be
        called repeatedly to reset the Program.
    */
    void initializeParsing();

    /** Parse an ELF given by filename. If recursiveDependencies is true,
        process all shared library dependencies immediately. This function can
        be called repeatedly to add Modules to a Program.
    */
    Module *parse(const std::string &filename, bool recursiveDependencies = false);

    /** Parse the ELF in filename with a specific role (e.g. Library::ROLE_LIBC).
        If role is Library::ROLE_UNKNOWN, the role will be guessed based on
        filename (this is the behavior of the other parse() override).
    */
    Module *parse(const std::string &filename, Library::Role role,
        bool recursiveDependencies = false);

    /** Parse the ELF or Windows PE executable in filename for a specific role,
        using the symbol table given in symbolFile (in ELF or .csv form).
    */
    Module *parse(const std::string &filename, const std::string &symbolFile,
        Library::Role role, bool recursiveDependencies = false);

    /** Recursively process all shared library dependencies. Can be called
        repeatedly with no issues. Normally called after all parse() calls if
        doing uniongen or recursive analyses.
    */
    void parseRecursiveDependencies();

    /** Returns the root Chunk, Program. */
    Program *getProgram() const { return setup.getConductor()->getProgram(); }

    /** Returns the list of ELF files referenced, which may or may not be
        parsed. Check Library::getModule() to access parsed libraries.
    */
    LibraryList *getLibraryList() const { return getProgram()->getLibraryList(); }

    /** Returns the ConductorSetup to allow more complex operations. */
    ConductorSetup *getSetup() { return &setup; }

    /** Returns the current Conductor, needed for many operations. */
    Conductor *getConductor() const { return setup.getConductor(); }

    /** Prints a Chunk to the console for debugging. Uses ChunkDumper. */
    template <typename ChunkType>
    void dump(ChunkType *chunk);

    /** Generates an output ELF into outputName. If only one Module is present
        in the Program, uses mirrorgen; otherwise, uses uniongen.
    */
    void generate(const std::string &outputName);

    /** Generates an output ELF into outputName. If isUnion is true, use
        uniongen, otherwise mirrorgen.
    */
    void generate(const std::string &outputName, bool isUnion);
public:
    // Public functions, but this interface could change.
    bool parseLoggingEnvVar(const char *envVar = "EGALITO_DEBUG");
    void muteOutput();
    bool setLogLevel(const char *logname, int level);
    void prepareForGeneration(bool isUnion);
    void assignNewFunctionAddresses();
};

template <typename ChunkType>
void EgalitoInterface::dump(ChunkType *chunk) {
    ChunkDumper dump;
    chunk->accept(&dump);
}

#endif
