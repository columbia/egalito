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

    this->elf = new ElfMap(executable);
    setBaseAddress(elf, 0x4000000);

    this->conductor = new Conductor();
    conductor->parseExecutable(elf);

    if(injectEgalito) {
        this->egalito = new ElfMap("./libegalito.so");
        setBaseAddress(egalito, 0x8000000l);  // can handle NULL ElfMap

        auto egalitoLib = new SharedLib("(egalito)", "(egalito)", egalito);
        conductor->getLibraryList()->add(egalitoLib);
        conductor->parseEgalito(egalito, egalitoLib);
    }

    if(withSharedLibs) {
        conductor->parseLibraries();
    }

    // set base addresses for any shared libraries that were pulled in
    int i = 0;
    for(auto lib : *conductor->getLibraryList()) {
        //if(lib == egalitoLib) continue;

        if(setBaseAddress(lib->getElfMap(), 0xa0000000 + i*0x1000000)) {
            i ++;
        }
    }

    if(withSharedLibs) {
        conductor->resolvePLTLinks();
    }
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
    auto module = conductor->getMainSpace()->getModule();
    Generator generator(useDisps);

    for(auto lib : *conductor->getLibraryList()) {
        LOG(1, "lib " << lib->getShortName());
        for(auto dep : lib->getParentDependList()) {
            LOG(1, "    parent dep " << dep->getShortName());
        }
        for(auto dep : lib->getDependencyList()) {
            LOG(1, "    dep " << dep->getShortName());
        }
    }

    generator.pickAddressesInSandbox(module, sandbox);
    for(auto lib : *conductor->getLibraryList()) {
        if(!lib->getElfSpace()) continue;
        //LOG(1, "moving code for " << lib->getElfSpace()->getModule()->getName());
        generator.pickAddressesInSandbox(
            lib->getElfSpace()->getModule(), sandbox);
    }
}

void ConductorSetup::copyCodeToNewAddresses(bool useDisps) {
    auto module = conductor->getMainSpace()->getModule();
    Generator generator(useDisps);

    generator.copyCodeToSandbox(module, sandbox);
    for(auto lib : *conductor->getLibraryList()) {
        if(!lib->getElfSpace()) continue;
        //LOG(1, "copying code for " << lib->getElfSpace()->getModule()->getName());
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
#if 1
    return CIter::named(conductor->getMainSpace()->getModule()->getFunctionList())
        ->find("_start")->getAddress();
#else
    // this is the original entry point address
    return elf->getEntryPoint() + elf->getBaseAddress();
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
