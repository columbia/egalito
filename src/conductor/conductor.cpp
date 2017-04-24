#include "conductor.h"
#include "elf/elfmap.h"
#include "generate/debugelf.h"
#include "pass/resolveplt.h"
#include "pass/relocdata.h"
#include "pass/fixjumptables.h"
#include "pass/fixdataregions.h"
#include "pass/libchacks.h"
#include "transform/data.h"
#include "log/log.h"

Conductor::Conductor() {
    forest = new ElfForest();
    program = new Program(forest->getSpaceList());
}

Conductor::~Conductor() {
    delete forest;
    delete program;
}

void Conductor::parseExecutable(ElfMap *elf) {
    parse(elf, nullptr);
}

void Conductor::parseEgalito(ElfMap *elf, SharedLib *library) {
    ElfSpace *space = new ElfSpace(elf, library);
    library->setElfSpace(space);
    space->findDependencies(getLibraryList());
    space->buildDataStructures();
    getSpaceList()->addEgalito(space);
    program->add(space->getModule());
}

void Conductor::parseLibraries() {
    // we use an index here because the list can change as we iterate
    for(size_t i = 0; i < getLibraryList()->getCount(); i ++) {
        auto library = getLibraryList()->get(i);
        if(library->getElfMap() == getSpaceList()->getEgalito()->getElfMap()) {
            continue;
        }
        parse(library->getElfMap(), library);
    }
}

void Conductor::parse(ElfMap *elf, SharedLib *library) {
    ElfSpace *space = new ElfSpace(elf, library);
    if(library) library->setElfSpace(space);
    space->findDependencies(getLibraryList());
    space->buildDataStructures();
    getSpaceList()->add(space, library == nullptr);
    if(library == nullptr) {
        program->addMain(space->getModule());
    }
    else {
        program->add(space->getModule());
    }
}

void Conductor::resolvePLTLinks() {
    ResolvePLTPass resolvePLT(program);
    program->accept(&resolvePLT);

    LibcHacksPass libcHacks(program);
    getLibraryList()->getLibc()->getElfSpace()->getModule()->accept(&libcHacks);
}

void Conductor::fixDataSections() {
    loadTLSData();

    for(auto module : CIter::children(program)) {
        fixDataSection(module);
    }
}

void Conductor::fixDataSection(Module *module) {
    RelocDataPass relocData(module->getElfSpace(), this);
    module->accept(&relocData);

    FixJumpTablesPass fixJumpTables;
    module->accept(&fixJumpTables);

    FixDataRegionsPass fixDataRegions;
    module->accept(&fixDataRegions);
}

void Conductor::loadTLSData() {
#if 0
    auto module = getMainSpace()->getModule();
    DataLoader loader;
    mainThreadPointer = loader.setupMainData(module, 0xd0000000);

    int i = 1;
    for(auto lib : *getLibraryList()) {
        if(!lib->getElfSpace()) continue;
        auto t = loader.loadLibraryTLSData(
            lib->getElfSpace()->getModule(), 0xd0000000 + i*0x1000000);
        i ++;

#ifdef ARCH_X86_64
        if(lib == getLibraryList()->getLibc()) {
            mainThreadPointer = t;
        }
#endif
    }
#else
    const static address_t base = 0xd0000000;
    DataLoader dataLoader(base);

    // calculate size
    size_t size = 0;
    for(auto module : CIter::children(program)) {
        auto tls = module->getDataRegionList()->getTLS();
        if(tls) size += tls->getSize();
    }

    // allocate headers
    address_t offset = 0;
    mainThreadPointer = dataLoader.allocateTLS(size, &offset);

    // copy in individual TLS regions
    for(auto module : CIter::children(program)) {
#ifdef ARCH_X86_64
        if(module == program->getMain()) continue;
#endif

        auto tls = module->getDataRegionList()->getTLS();
        if(tls) {
            LOG(1, "copying in TLS for " << module->getName() << " at "
                << offset << " size " << tls->getSize());
            tls->setTLSOffset((base + offset) - mainThreadPointer);
            dataLoader.copyTLSData(module->getElfSpace()->getElfMap(),
                tls, offset);
            offset += tls->getSize();
        }
    }

#ifdef ARCH_X86_64
    // x86: place executable's TLS (if present) right before the header
    auto executable = program->getMain();
    if(auto tls = executable->getDataRegionList()->getTLS()) {
        LOG(1, "copying in TLS for " << executable->getName() << " at "
            << offset << " size " << tls->getSize());
        tls->setTLSOffset((base + offset) - mainThreadPointer);
        dataLoader.copyTLSData(executable->getElfSpace()->getElfMap(),
            tls, offset);
        offset += tls->getSize();
    }
#endif
#endif
}

void Conductor::writeDebugElf(const char *filename, const char *suffix) {
    DebugElf debugElf;

    for(auto module : CIter::children(program)) {
        for(auto func : CIter::functions(module)) {
            debugElf.add(func, suffix);
        }
    }

    debugElf.writeTo(filename);
}

void Conductor::acceptInAllModules(ChunkVisitor *visitor, bool inEgalito) {
    for(auto module : CIter::children(program)) {
        if(inEgalito && module == program->getEgalito()) continue;

        module->accept(visitor);
    }
}
