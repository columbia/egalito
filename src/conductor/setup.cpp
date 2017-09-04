#include <cassert>
#include "setup.h"
#include "conductor.h"
#include "transform/generator.h"
#include "load/segmap.h"
#include "chunk/dump.h"
#include "operation/find2.h"
#include "log/registry.h"
#include "log/log.h"

address_t runEgalito(ElfMap *elf, ElfMap *egalito);

void ConductorSetup::parseElfFiles(const char *executable,
    bool withSharedLibs, bool injectEgalito) {

    this->conductor = new Conductor();

    this->elf = new ElfMap(executable);
    setBaseAddress(elf, 0x4000000);
    conductor->parseExecutable(elf);

    entrySymbol = conductor->getMainSpace()->getSymbolList()->find(
        elf->getEntryPoint() + elf->getBaseAddress());

    if(injectEgalito) {
        this->egalito = new ElfMap("./libegalito.so");
        //setBaseAddress(egalito, 0x8000000l);  // use address assigned below
        conductor->parseEgalito(egalito);
    }

    if(withSharedLibs) {
        conductor->parseLibraries();
    }

    // set base addresses for any shared libraries that were pulled in
    int i = 0;
    for(auto lib : *conductor->getLibraryList()) {
        if(lib->getElfMap() == this->elf) continue;

        if(setBaseAddress(lib->getElfMap(), 0xa0000000 + i*0x1000000)) {
            i ++;
        }
    }

    if(withSharedLibs) {
        conductor->resolvePLTLinks();
    }
}

#define ROUND_DOWN(x)   ((x) & ~0xfff)
#define ROUND_UP(x)     (((x) + 0xfff) & ~0xfff)

void ConductorSetup::injectLibrary(const char *filename) {
    if(auto elfmap = new ElfMap(filename)) {
        conductor->parseAddOnLibrary(elfmap);
        setBaseAddress(elfmap, 0xb0000000);

        Module *module = nullptr;
        for(auto space : conductor->getSpaceList()->iterable()) {
            if(space->getElfMap() == elfmap) {
                module = space->getModule();
                break;
            }
        }

        for(auto region : CIter::regions(module)) {
            if(region == module->getDataRegionList()->getTLS()) continue;

            region->updateAddressFor(elfmap->getBaseAddress());
        }
    }
    conductor->resolvePLTLinks();
}

void ConductorSetup::makeLoaderSandbox() {
    auto backing = MemoryBacking(10 * 0x1000 * 0x1000);
    this->sandbox = new SandboxImpl<MemoryBacking,
        WatermarkAllocator<MemoryBacking>>(backing);
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

/*
    // resolve all relocations in data sections
    conductor.fixDataSections();

    conductor.writeDebugElf("symbols.elf");
*/

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

address_t ConductorSetup::getEntryPoint() {
#if 0
    auto module = conductor->getMainSpace()->getModule();
    if(auto f = CIter::named(module->getFunctionList())->find("_start")) {
        return f->getAddress();
    }
    if(auto f = CIter::named(module->getFunctionList())
        ->find("_rt0_arm64_linux")) {

        return f->getAddress();
    }
    LOG(0, "entry point not found");
    return 0;
#else
    auto module = conductor->getMainSpace()->getModule();
    if(auto f = CIter::named(module->getFunctionList())->find(
        entrySymbol->getName())) {

        return f->getAddress();
    }

    LOG(0, "entry point not found");
    return 0;
#endif
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
