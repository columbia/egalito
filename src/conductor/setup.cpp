#include <cassert>
#include "setup.h"
#include "conductor.h"
#include "transform/generator.h"
#include "load/segmap.h"
#include "chunk/dump.h"
#include "chunk/find2.h"
#include "log/registry.h"
#include "log/log.h"

address_t runEgalito(ElfMap *elf, ElfMap *egalito);

void ConductorSetup::parseElfFiles(const char *executable,
    bool withSharedLibs, bool injectEgalito) {

    this->elf = new ElfMap(executable);
    setBaseAddress(elf, 0x4000000);

    this->conductor = new Conductor();
    if(withSharedLibs) {
        conductor->parseRecursive(elf);
    }
    else {
        conductor->parse(elf, nullptr);
    }

    if(injectEgalito) {
        this->egalito = new ElfMap("./libegalito.so");
        setBaseAddress(egalito, 0x8000000l);  // can handle NULL ElfMap

        auto egalitoLib = new SharedLib("(egalito)", "(egalito)", egalito);
        conductor->getLibraryList()->add(egalitoLib);
        conductor->parseEgalito(egalito, egalitoLib);
    }

    // set base addresses for any shared libraries that were pulled in
    int i = 0;
    for(auto lib : *conductor->getLibraryList()) {
        //if(lib == egalitoLib) continue;

        if(setBaseAddress(lib->getElfMap(), 0xa0000000 + i*0x1000000)) {
            i ++;
        }
    }
}

void ConductorSetup::makeLoaderSandbox() {
    auto backing = MemoryBacking(10 * 0x1000 * 0x1000);
    this->sandbox = new SandboxImpl<MemoryBacking,
        WatermarkAllocator<MemoryBacking>>(backing);
}

void ConductorSetup::makeFileSandbox(const char *outputFile) {
    auto backing = ElfBacking(conductor->getMainSpace(), outputFile);
    this->sandbox = new SandboxImpl<ElfBacking,
        WatermarkAllocator<ElfBacking>>(backing);
}

void ConductorSetup::moveCode() {
    auto module = conductor->getMainSpace()->getModule();
    Generator generator;

    // 1. assign new addresses to all code
    generator.pickAddressesInSandbox(module, sandbox);
    for(auto lib : *conductor->getLibraryList()) {
        if(!lib->getElfSpace()) continue;
        generator.pickAddressesInSandbox(
            lib->getElfSpace()->getModule(), sandbox);
    }

    // 2. copy code to the new addresses
    generator.copyCodeToSandbox(module, sandbox);
    for(auto lib : *conductor->getLibraryList()) {
        if(!lib->getElfSpace()) continue;
        generator.copyCodeToSandbox(
            lib->getElfSpace()->getModule(), sandbox);
    }

    // 3. make code executable, or change permissions
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
        f = ChunkFind2(conductor).findFunctionInSpace(function, space);
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
