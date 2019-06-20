#ifndef EGALITO_CONDUCTOR_SETUP_H
#define EGALITO_CONDUCTOR_SETUP_H

#include <vector>
#include <string>
#include "config.h"
#include "filetype.h"
#include "elf/elfmap.h"
#include "elf/elfspace.h"
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
    ElfMap *elf;
    ElfMap *egalito;
    Conductor *conductor;
    address_t sandboxBase;
public:
    ConductorSetup() : elf(nullptr), egalito(nullptr), conductor(nullptr),
        sandboxBase(SANDBOX_BASE_ADDRESS) {}
    Module *parseElfFiles(const char *executable, bool withSharedLibs = true,
        bool injectEgalito = false);
    Module *injectElfFiles(const char *executable, bool withSharedLibs = true,
        bool injectEgalito = false);
    Module *injectElfFiles(const char *executable, Library::Role role,
        bool withSharedLibs = true, bool injectEgalito = false);
    Module *injectFiles(const char *executable, const char *symbolFile,
        ExeFileType fileType = EXE_UNKNOWN, Library::Role role = Library::ROLE_UNKNOWN,
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
    bool generateKernel(const char *outputFile);
    void moveCode(Sandbox *sandbox, bool useDisps = true);
public:
    void moveCodeAssignAddresses(Sandbox *sandbox, bool useDisps);
    void copyCodeToNewAddresses(Sandbox *sandbox, bool useDisps);
    void moveCodeMakeExecutable(Sandbox *sandbox);
public:
    ElfMap *getElfMap() const { return elf; }
    ElfMap *getEgalitoElfMap() const { return egalito; }
    Conductor *getConductor() const { return conductor; }
public:
    void dumpElfSpace(ElfSpace *space);
    void dumpFunction(const char *function, ElfSpace *space = nullptr);
    address_t getEntryPoint();
private:
    void parseEgalito(bool fromArchive = false);
    void findEntryPointFunction();
    void setBaseAddresses();
    bool setBaseAddress(Module *module, ElfMap *map, address_t base);
};

#endif
