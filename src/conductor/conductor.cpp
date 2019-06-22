#include <cassert>
#include "config.h"
#include "conductor.h"
#include "parseoverride.h"
#include "passes.h"
#include "chunk/ifunc.h"
#include "chunk/tls.h"
#include "elf/elfmap.h"
#include "elf/elfdynamic.h"
#include "exefile/exefile.h"
#include "generate/debugelf.h"
#include "operation/find2.h"
#include "pass/handlerelocs.h"
#include "pass/handledatarelocs.h"
#include "pass/handlecopyrelocs.h"
#include "pass/injectbridge.h"
#include "chunk/serializer.h"
#include "pass/internalcalls.h"
#include "pass/resolveplt.h"
#include "pass/resolvetls.h"
#include "pass/fixjumptables.h"
#include "pass/ifunclazy.h"
#include "pass/fixdataregions.h"
#include "pass/resolveexternallinks.h"
#include "pass/populateplt.h"
#include "pass/relocheck.h"
#include "pass/encodingcheckpass.h"
#include "pass/findinitfuncs.h"
#include "disasm/objectoriented.h"
#include "transform/data.h"

#include "parseoverride.h"

#ifdef USE_WIN64_PE
#include "pe/pemap.h"
#endif

#include "log/log.h"
#include "log/temp.h"

IFuncList *egalito_ifuncList __attribute__((weak));

Conductor::Conductor() : mainThreadPointer(0), ifuncList(nullptr) {
    program = new Program();
    program->setLibraryList(new LibraryList());

    ParseOverride::getInstance()->parseFromEnvironmentVar();
}

Conductor::~Conductor() {
    delete program;
}

Module *Conductor::parseAnything(const std::string &fullPath, Library::Role role) {
    return parseAnythingWithSymbols(fullPath, "", ExeFile::EXE_UNKNOWN, role);
}

Module *Conductor::parseAnythingWithSymbols(const std::string &fullPath,
    const std::string &symbolFile, ExeFile::ExeFileType fileType,
    Library::Role role) {

    if(role == Library::ROLE_UNKNOWN) {
        role = Library::guessRole(fullPath);
    }
    auto exeMap = ExeFile::createMap(fullPath);
    auto internalName = Library::determineInternalName(fullPath, role);
    auto library = new Library(internalName, role);
    library->setResolvedPath(fullPath);
    return parse(exeMap, library, symbolFile);
}

Module *Conductor::parseExecutable(ElfMap *elf, const std::string &fullPath) {
    auto library = new Library("(executable)", Library::ROLE_MAIN);
    library->setResolvedPath(fullPath);
    return parse(elf, library);
}

Module *Conductor::parseEgalito(ElfMap *elf, const std::string &fullPath) {
    auto library = new Library("(egalito)", Library::ROLE_EGALITO);
    library->setResolvedPath(fullPath);
    return parse(elf, library);
}

void Conductor::parseEgalitoExeFileOnly(ElfMap *elf, Module *module,
    const std::string &fullPath) {

    auto library = module->getLibrary();
    library->setResolvedPath(fullPath);

    ExeFile *exeFile = new ElfExeFile(elf, library->getName(),
        library->getResolvedPath());

    LOG(1, "\n=== BUILDING ELF DATA STRUCTURES for ["
        << exeFile->getName() << "] ===");
    exeFile->parseSymbolsAndRelocs();
    //ElfDynamic(getLibraryList()).parse(elf, library);

    module->setExeFile(exeFile);
    //exeFile->setModule(module);

    //LOG(1, "--- RUNNING DEFAULT ELF PASSES for ["
    //    << exeFile->getName() << "] ---");
    //ConductorPasses(this).newExePasses(exeFile);
    // needs module->getExeFile()
    ConductorPasses(this).reloadedArchivePasses(module);
}

void Conductor::parseLibraries() {
    auto iterable = getLibraryList()->getChildren()->getIterable();

    // we use an index here because the list can change as we iterate
    for(size_t i = 0; i < iterable->getCount(); i ++) {
        auto library = iterable->get(i);
        if(library->getModule()) {
            continue;  // already parsed
        }

        ElfMap *elf = new ElfMap(library->getResolvedPathCStr());
        parse(elf, library);
    }
}

Module *Conductor::parseAddOnLibrary(ElfMap *elf) {
    auto library = new Library("(addon)", Library::ROLE_SUPPORT);
    auto module = parse(elf, library);
    return module;
}

Module *Conductor::parseExtraLibrary(ElfMap *elf, const std::string &name) {
    auto library = new Library("(extra)-" + name, Library::ROLE_EXTRA);
    library->setResolvedPath(name);
    auto module = parse(elf, library);
    return module;
}

Module *Conductor::parse(ExeMap *exeMap, Library *library,
    const std::string &symbolFile) {

    program->add(library);  // add current lib before its dependencies
    ExeFile *exeFile = nullptr;
    if(auto elf = dynamic_cast<ElfMap *>(exeMap)) {
        exeFile = new ElfExeFile(elf, library->getName(),
            library->getResolvedPath());
    }
    else if(auto pe = dynamic_cast<PEMap *>(exeMap)) {
        exeFile = new PEExeFile(pe, library->getName(),
            library->getResolvedPath());
    }

    ParseOverride::getInstance()->setCurrentModule("module-" + library->getName());

    LOG(1, "\n=== BUILDING DATA STRUCTURES for ["
        << exeFile->getName() << "] ===");
    exeFile->parseSymbolsAndRelocs(symbolFile);
    if(auto elfFile = exeFile->asElf()) {
        ElfDynamic(getLibraryList()).parse(elfFile->getMap(), library);
    }

    LOG(1, "--- RUNNING DEFAULT PASSES for ["
        << exeFile->getName() << "] ---");
    auto module = ConductorPasses(this).newExePasses(exeFile);
    program->add(module);
    module->setParent(program);

    ParseOverride::getInstance()->clearCurrentModule();

    return module;
}

void Conductor::parseEgalitoArchive(const char *archive) {
    ChunkSerializer serializer;
    Chunk *newData = serializer.deserialize(archive);

    if(!newData) {
        LOG(1, "Error parsing archive [" << archive << "]");
        return;  // No data present
    }
    else if(auto p = dynamic_cast<Program *>(newData)) {
        LOG(1, "Using full Chunk tree from archive [" << archive << "]");
        this->program = p;
    }
    /*else if(auto module = dynamic_cast<Module *>(newData)) {
        LOG(1, "Using Module \"" << module->getName()
            << "\" from archive [" << archive << "]");
        program->add(module);
    }*/
    else {
        LOG(1, "Not using archive, only a subset of the Chunk tree is present");
    }

    ConductorPasses(this).newArchivePasses(program);
}

void Conductor::resolvePLTLinks() {
    ResolvePLTPass resolvePLT(this);
    program->accept(&resolvePLT);

    if(program->getEgalito()) {
        PopulatePLTPass populatePLT(this);
        program->accept(&populatePLT);
    } else {
        LOG(5, "Warning: not populating PLT entries");
    }
}

void Conductor::resolveTLSLinks() {
    ResolveTLSPass resolveTLS;
    program->accept(&resolveTLS);
}

void Conductor::resolveData(bool multipleElf, bool justBridge) {
    if(auto egalito = program->getEgalito()) {
        InjectBridgePass bridge(egalito->getExeFile()->getRelocList());
        egalito->accept(&bridge);
    }
    if(justBridge) return;

    for(auto module : CIter::modules(program)) {
        auto exeFile = module->getExeFile();
        auto elfMap = ExeAccessor::map<ElfMap>(exeFile);
        if(!elfMap) continue;

        if(resolveFinished.count(module)) continue;

        LOG(10, "[[[0 HandleDataRelocsInternalStrong]]] " << module->getName());
        RUN_PASS(HandleDataRelocsInternalStrong(exeFile->getRelocList(), this), module);

        LOG(10, "[[[1 HandleRelocsWeak]]] " << module->getName());
        HandleRelocsWeak handleRelocsPass(
            elfMap, exeFile->getRelocList());
        module->accept(&handleRelocsPass);

        LOG(10, "[[[2 HandleDataRelocsExternalStrong]]] " << module->getName());
        HandleDataRelocsExternalStrong pass1(exeFile->getRelocList(), this);
        module->accept(&pass1);

        LOG(10, "[[[3 HandleDataRelocsInternalWeak]]] " << module->getName());
        HandleDataRelocsInternalWeak pass2(exeFile->getRelocList());
        module->accept(&pass2);

        LOG(10, "[[[4 HandleDataRelocsExternalWeak]]] " << module->getName());
        HandleDataRelocsExternalWeak pass3(exeFile->getRelocList(), this);
        module->accept(&pass3);

        // requires DataVariables
        RUN_PASS(FindInitFuncs(), module);
    }

    if(multipleElf) {
        ResolveExternalLinksPass resolveExternalLinks(this);
        program->accept(&resolveExternalLinks);
    }
}

void Conductor::resolveVTables() {
    for(auto module : CIter::modules(program)) {
        auto exeFile = module->getExeFile();
        auto elfMap = ExeAccessor::map<ElfMap>(module);
        if(!exeFile || !elfMap) continue;

        if(resolveFinished.count(module)) continue;
        resolveFinished.insert(module);

        // this needs data regions
        module->setVTableList(DisassembleVTables().makeVTableList(
            elfMap,
            exeFile->getSymbolList(),
            exeFile->getRelocList(), module, program));
    }
}

void Conductor::setupIFuncLazySelector() {
    this->ifuncList = new IFuncList();
    ::egalito_ifuncList = ifuncList;

#ifndef EXPERIMENTAL_ARCHIVE
    IFuncLazyPass ifuncLazyPass(ifuncList);
    program->accept(&ifuncLazyPass);
#endif
}

void Conductor::fixDataSections(bool allocateTLS) {
    const static address_t base = 0x20000000;
    if(allocateTLS) {
        allocateTLSArea(base);
        loadTLSData();
    }

    FixDataRegionsPass fixDataRegions;
    program->accept(&fixDataRegions);

    // NOTE: this overwrites DataVariables, which are stored as
    // absolute values instead of relative, with relative values.
    // Should do this more efficiently.
    FixJumpTablesPass fixJumpTables;
    program->accept(&fixJumpTables);

    HandleCopyRelocs handleCopyRelocs(this);
    program->accept(&handleCopyRelocs);

    if(allocateTLS) backupTLSData();
}

EgalitoTLS *Conductor::getEgalitoTLS() const {
    return reinterpret_cast<EgalitoTLS *>(
        mainThreadPointer - sizeof(EgalitoTLS));
}

void Conductor::allocateTLSArea(address_t base) {
#ifdef USE_LOADER
    DataLoader dataLoader;

    // calculate size
    size_t size = sizeof(EgalitoTLS);
    for(auto module : CIter::modules(program)) {
        auto tls = module->getDataRegionList()->getTLS();
        if(tls) size += tls->getSize();
    }

    if(!size) return;


    // allocate headers
    address_t offset = 0;
    mainThreadPointer = dataLoader.allocateTLS(base, size, &offset);
    LOG(1, "mainThreadPointer is at " << std::hex << mainThreadPointer);
    this->TLSOffsetFromTCB = (base + offset) - mainThreadPointer;

    // actually assign address
    for(auto module : CIter::modules(program)) {
        auto tls = module->getDataRegionList()->getTLS();
        if(tls) {
#ifdef ARCH_X86_64
            if(module == program->getMain()) continue;
#endif
            tls->setBaseAddress(base + offset);
            tls->setTLSOffset((base + offset) - mainThreadPointer);
            offset += tls->getSize();
        }
    }

#ifdef ARCH_X86_64
    // x86: place executable's TLS (if present) right before the header
    if(auto executable = program->getMain()) {
        if(auto tls = executable->getDataRegionList()->getTLS()) {
            tls->setBaseAddress(base + offset);
            tls->setTLSOffset((base + offset) - mainThreadPointer);
            offset += tls->getSize();
        }
    }
#endif
#endif
}

void Conductor::loadTLSData() {
    DataLoader dataLoader;
    for(auto module : CIter::modules(program)) {
        auto tls = module->getDataRegionList()->getTLS();
        if(tls) {
            dataLoader.loadRegion(tls);
        }
    }
}

void Conductor::backupTLSData() {
    for(auto module : CIter::modules(program)) {
        auto tls = module->getDataRegionList()->getTLS();
        if(tls) {
            tls->saveDataBytes();
        }
    }
}

void Conductor::loadTLSDataFor(address_t tcb) {
    DataLoader dataLoader;
    address_t address = tcb + TLSOffsetFromTCB;
    for(auto module : CIter::modules(program)) {
        auto tls = module->getDataRegionList()->getTLS();
        if(tls) {
            address = dataLoader.loadRegionTo(address, tls);
        }
    }
}

void Conductor::writeDebugElf(const char *filename, const char *suffix) {
    DebugElf debugElf;

    for(auto module : CIter::modules(program)) {
        for(auto func : CIter::functions(module)) {
            debugElf.add(func, suffix);
        }
    }

    debugElf.writeTo(filename);
}

void Conductor::acceptInAllModules(ChunkVisitor *visitor, bool inEgalito) {
    for(auto module : CIter::modules(program)) {
        if(!inEgalito && module == program->getEgalito()) continue;

        module->accept(visitor);
    }
}

ExeFile *Conductor::getMainExeFile() const {
    return getProgram()->getFirst()->getExeFile();
}

void Conductor::check() {
    ReloCheckPass checker;
    acceptInAllModules(&checker, true);

#ifdef ARCH_AARCH64
    EncodingCheckPass checker2;
    acceptInAllModules(&checker2, true);
#endif
}
