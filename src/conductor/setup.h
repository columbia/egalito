#ifndef EGALITO_CONDUCTOR_SETUP_H
#define EGALITO_CONDUCTOR_SETUP_H

#include <vector>
#include <string>
#include "config.h"
#include "filetype.h"
#include "elf/elfmap.h"
#include "exefile/exefile.h"
#include "transform/sandbox.h"

class Conductor;
class Sandbox;
class Symbol;

/** Main setup class for Egalito.

    Note: please call functions in the order they appear, i.e.
        parseElfFiles(),
        makeLoaderSandbox() / makeFileSandbox(),
        moveCode() OR its three components
            moveCodeAssignAddresses(),
            copyCodeToNewAddresses(),
            moveCodeMakeExecutable()
*/
class ConductorSetup {
private:
    Conductor *conductor;
    address_t sandboxBase;
public:
    ConductorSetup() : conductor(nullptr), sandboxBase(SANDBOX_BASE_ADDRESS) {}
    Module *parseElfFiles(const char *executable, bool withSharedLibs = true,
        bool injectEgalito = false);
    Module *injectElfFiles(const char *executable, bool withSharedLibs = true,
        bool injectEgalito = false);
    Module *injectElfFiles(const char *executable, Library::Role role,
        bool withSharedLibs = true, bool injectEgalito = false);
    Module *injectFiles(const char *executable, const char *symbolFile,
        ExeFile::ExeFileType fileType = ExeFile::EXE_UNKNOWN,
        Library::Role role = Library::ROLE_UNKNOWN,
        bool withSharedLibs = true, bool injectEgalito = false);
    void parseEgalitoArchive(const char *archive);
    void injectLibrary(const char *filename);
    std::vector<Module *> addExtraLibraries(
        const std::vector<std::string> &filenames);
    void ensureBaseAddresses();
    void createNewProgram();  // optional
    Sandbox *makeLoaderSandbox();
    ShufflingSandbox *makeShufflingSandbox();
    Sandbox *makeFileSandbox(const char *outputFile);
    Sandbox *makeStaticExecutableSandbox(const char *outputFile);
    Sandbox *makeKernelSandbox(const char *outputFile);
    bool generateStaticExecutable(const char *outputFile);
    bool generateMirrorELF(const char *outputFile);
    bool generateMirrorELF(const char *outputFile,
        const std::vector<Function *> &order);
    bool generateKernel(const char *outputFile);
    void moveCode(Sandbox *sandbox, bool useDisps = true);
public:
    void moveCodeAssignAddresses(Sandbox *sandbox, bool useDisps);
    void copyCodeToNewAddresses(Sandbox *sandbox, bool useDisps);
    void moveCodeMakeExecutable(Sandbox *sandbox);
public:
    ElfMap *getElfMap() const { return nullptr; }  // DEPRECATED function
    ElfMap *getEgalitoElfMap() const { return nullptr; }  // DEPRECATED function
    Conductor *getConductor() const { return conductor; }
public:
    void dumpElfSpace(ElfSpace *space) {}  // DEPRECATED function.
    void dumpModule(Module *module);
    void dumpFunction(const char *function, Module *module = nullptr);
    address_t getEntryPoint();
private:
    void parseEgalito(bool fromArchive = false);
    void findEntryPointFunction();
    void setBaseAddresses();
    bool setBaseAddress(Module *module, ExeMap *map, address_t base);
};

#endif
