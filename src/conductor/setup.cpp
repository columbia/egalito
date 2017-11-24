#include <cassert>
#include "setup.h"
#include "conductor.h"
#include "transform/generator.h"
#include "load/segmap.h"
#include "chunk/dump.h"
#include "operation/find2.h"
#include "pass/clearspatial.h"
#include "log/registry.h"
#include "log/log.h"

address_t runEgalito(ElfMap *elf, ElfMap *egalito);

Conductor *egalito_conductor __attribute__((weak));
Sandbox *egalito_sandbox __attribute__((weak));

void ConductorSetup::parseElfFiles(const char *executable,
    bool withSharedLibs, bool injectEgalito) {

    this->conductor = new Conductor();
    ::egalito_conductor = conductor;

    this->elf = new ElfMap(executable);
    conductor->parseExecutable(elf);

    findEntryPointFunction();

    if(injectEgalito) {
        this->egalito = new ElfMap("./libegalito.so");
        conductor->parseEgalito(egalito);
    }

    if(withSharedLibs) {
        conductor->parseLibraries();
    }

    if(withSharedLibs) {
        conductor->resolvePLTLinks();
    }
    conductor->resolveTLSLinks();
    conductor->resolveWeak();
    conductor->resolveVTables();

    conductor->check();

    // At this point, all the effort for resolving the links should be
    // performed (except for special cases)
    setBaseAddress(elf, 0x4000000);
    // set base addresses for any shared libraries that were pulled in
    int i = 0;
    for(auto lib : *conductor->getLibraryList()) {
        if(lib->getElfMap() == this->elf) continue;

        if(setBaseAddress(lib->getElfMap(), 0xa0000000 + i*0x1000000)) {
            i ++;
        }
    }

    // change the address of regions accordingly (including executable's)
    ClearSpatialPass clearSpatial;
    for(auto module : CIter::children(conductor->getProgram())) {
        auto baseAddress = module->getElfSpace()->getElfMap()->getBaseAddress();
        for(auto region : CIter::regions(module)) {
            region->updateAddressFor(baseAddress);
            module->accept(&clearSpatial);
        }
    }
}

void ConductorSetup::parseEgalitoArchive(const char *archive) {
    this->conductor = new Conductor();

    this->elf = nullptr;
    this->egalito = nullptr;

    conductor->parseEgalitoArchive(archive);
}

void ConductorSetup::injectLibrary(const char *filename) {
    if(auto elfmap = new ElfMap(filename)) {
        auto module = conductor->parseAddOnLibrary(elfmap);
        setBaseAddress(elfmap, 0xb0000000);

        for(auto region : CIter::regions(module)) {
            region->updateAddressFor(elfmap->getBaseAddress());
        }
    }
    conductor->resolvePLTLinks();
}

void ConductorSetup::makeLoaderSandbox() {
    auto backing = MemoryBacking(10 * 0x1000 * 0x1000);
    this->sandbox = new SandboxImpl<MemoryBacking,
        WatermarkAllocator<MemoryBacking>>(backing);
    ::egalito_sandbox = sandbox;
}

void ConductorSetup::makeFileSandbox(const char *outputFile) {
    // auto backing = ExeBacking(conductor->getMainSpace(), outputFile);
    // this->sandbox = new SandboxImpl<ExeBacking,
    //     WatermarkAllocator<ExeBacking>>(backing);
    auto backing = ObjBacking(conductor->getMainSpace(), outputFile);
    this->sandbox = new SandboxImpl<ObjBacking,
        WatermarkAllocator<ObjBacking>>(backing);
}

void ConductorSetup::moveCode(bool useDisps) {
    // 1. assign new addresses to all code
    moveCodeAssignAddresses(useDisps);

    // 2. copy code to the new addresses
    copyCodeToNewAddresses(useDisps);

    // 3. make code executable, or change permissions
    moveCodeMakeExecutable();
}

void ConductorSetup::moveCodeAssignAddresses(bool useDisps) {
    Generator generator(useDisps);

    for(auto lib : *conductor->getLibraryList()) {
        LOG(1, "depends for library " << lib->getShortName());
        for(auto dep : lib->getParentDependList()) {
            LOG(1, "    parent dep " << dep->getShortName());
        }
        for(auto dep : lib->getDependencyList()) {
            LOG(1, "    dep " << dep->getShortName());
        }
    }

    for(auto lib : *conductor->getLibraryList()) {
        if(!lib->getElfSpace()) continue;
        generator.pickAddressesInSandbox(
            lib->getElfSpace()->getModule(), sandbox);
    }
}

void ConductorSetup::copyCodeToNewAddresses(bool useDisps) {
    Generator generator(useDisps);

    for(auto lib : *conductor->getLibraryList()) {
        if(!lib->getElfSpace()) continue;
        generator.copyCodeToSandbox(
            lib->getElfSpace()->getModule(), sandbox);
    }
}

void ConductorSetup::moveCodeMakeExecutable() {
    sandbox->finalize();
}

void ConductorSetup::dumpElfSpace(ElfSpace *space) {
    ChunkDumper dumper;
    space->getModule()->accept(&dumper);
}

void ConductorSetup::dumpFunction(const char *function, ElfSpace *space) {
    Function *f = nullptr;
    if(space) {
        f = ChunkFind2(conductor)
            .findFunctionInModule(function, space->getModule());
    }
    else {
        f = ChunkFind2(conductor).findFunction(function);
    }

    ChunkDumper dumper;
    if(f) {
        f->accept(&dumper);
    }
    else {
        LOG(1, "Warning: can't find function [" << function << "] to dump");
    }
}

void ConductorSetup::findEntryPointFunction() {
    auto module = conductor->getMainSpace()->getModule();
    address_t elfEntry = elf->getEntryPoint();

    if(auto f = CIter::spatial(module->getFunctionList())->find(elfEntry)) {
        LOG(0, "found entry function [" << f->getName() << "]");
        conductor->getProgram()->setEntryPoint(f);
    }
    else {
        LOG(0, "WARNING: can't find entry point!");
    }
}

address_t ConductorSetup::getEntryPoint() {
    return getConductor()->getProgram()->getEntryPointAddress();
}

bool ConductorSetup::setBaseAddress(ElfMap *map, address_t base) {
    if(!map) return false;

    if(map->isSharedLibrary()) {
        LOG(1, "set base address to " << std::hex << base);
        map->setBaseAddress(base);
        return true;
    }
    else {
        map->setBaseAddress(0);
    }

    return false;
}
