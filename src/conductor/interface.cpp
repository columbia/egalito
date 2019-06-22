#include "interface.h"

#include "pass/fixenviron.h"
#include "pass/collapseplt.h"
#include "pass/promotejumps.h"
#include "pass/ldsorefs.h"
#include "pass/externalsymbollinks.h"
#include "pass/ifuncplts.h"
#include "log/registry.h"
#include "log/log.h"

EgalitoInterface::EgalitoInterface(bool verboseLogging, bool useLoggingEnvVar) {
    if(!verboseLogging) muteOutput();

    if(!parseLoggingEnvVar()) {
        LOG(1, "Failed to parse EGALITO_DEBUG environment variable");
    }
}

bool EgalitoInterface::parseLoggingEnvVar(const char *envVar) {
    return SettingsParser().parseEnvVar(envVar);
}

void EgalitoInterface::muteOutput() {
    GroupRegistry::getInstance()->muteAllSettings();
}

bool EgalitoInterface::setLogLevel(const char *logname, int level) {
    return GroupRegistry::getInstance()->applySetting(logname, level);
}

void EgalitoInterface::initializeParsing() {
    setup.createNewProgram();
}

Module *EgalitoInterface::parse(const std::string &filename, bool recursiveDependencies) {
    return setup.injectElfFiles(filename.c_str(), recursiveDependencies, false);
}

Module *EgalitoInterface::parse(const std::string &filename, Library::Role role,
    bool recursiveDependencies) {

    return setup.injectElfFiles(filename.c_str(), role, recursiveDependencies, false);
}

Module *EgalitoInterface::parse(const std::string &filename,
    const std::string &symbolFile, Library::Role role, bool recursiveDependencies) {

    return setup.injectFiles(filename.c_str(), symbolFile.c_str(),
        ExeFile::EXE_UNKNOWN, role, recursiveDependencies, false);
}

void EgalitoInterface::parseRecursiveDependencies() {
    setup.getConductor()->parseLibraries();
    setup.addExtraLibraries(std::vector<std::string>{});  // force resolve* functions
}

void EgalitoInterface::prepareForGeneration(bool isUnion) {
    if(isUnion) {
        FixEnvironPass fixEnviron;
        getProgram()->accept(&fixEnviron);
    }

    CollapsePLTPass collapsePLT(setup.getConductor());
    getProgram()->accept(&collapsePLT);

    PromoteJumpsPass promoteJumps;
    getProgram()->accept(&promoteJumps);
}

void EgalitoInterface::generate(const std::string &outputName) {
    auto count = getProgram()->getChildren()->genericGetSize();
    generate(outputName, count > 1);
}

void EgalitoInterface::generate(const std::string &outputName, bool isUnion) {
    auto program = getProgram();
    prepareForGeneration(isUnion);
    if(!isUnion) {
        // generate mirror executable.
        LOG(0, "Generating 1-1 executable [" << outputName << "]...");
        LdsoRefsPass ldsoRefs;
        program->accept(&ldsoRefs);

        ExternalSymbolLinksPass externalSymbolLinks;
        program->accept(&externalSymbolLinks);

        IFuncPLTs ifuncPLTs;
        program->accept(&ifuncPLTs);

        setup.generateMirrorELF(outputName.c_str());
    }
    else {
        // generate static executable.
        LOG(0, "Generating union executable [" << outputName << "]...");
        LdsoRefsPass ldsoRefs;
        program->accept(&ldsoRefs);
        IFuncPLTs ifuncPLTs;
        program->accept(&ifuncPLTs);

        setup.generateStaticExecutable(outputName.c_str());
    }
}

void EgalitoInterface::generate(const std::string &outputName,
    const std::vector<Function *> &order) {

    auto program = getProgram();
    prepareForGeneration(false);

    // generate mirror executable.
    LOG(0, "Generating 1-1 executable [" << outputName << "]...");
    LdsoRefsPass ldsoRefs;
    program->accept(&ldsoRefs);

    ExternalSymbolLinksPass externalSymbolLinks;
    program->accept(&externalSymbolLinks);

    IFuncPLTs ifuncPLTs;
    program->accept(&ifuncPLTs);

    setup.generateMirrorELF(outputName.c_str(), order);
}

void EgalitoInterface::assignNewFunctionAddresses() {
    auto sandbox = setup.makeLoaderSandbox();
    setup.moveCodeAssignAddresses(sandbox, true);
}
