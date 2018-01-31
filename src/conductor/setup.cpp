#include <cassert>
#include <unistd.h>
#include <climits>
#include <cstring>
#include "config.h"
#include "setup.h"
#include "conductor.h"
#include "transform/generator.h"
#include "load/segmap.h"
#include "load/emulator.h"
#include "chunk/dump.h"
#include "operation/find2.h"
#include "pass/clearspatial.h"
#include "log/registry.h"
#include "log/log.h"

address_t runEgalito(ElfMap *elf, ElfMap *egalito);

ConductorSetup *egalito_conductor_setup __attribute__((weak));
Conductor *egalito_conductor __attribute__((weak));

void ConductorSetup::parseElfFiles(const char *executable,
    bool withSharedLibs, bool injectEgalito) {

    this->conductor = new Conductor();
    ::egalito_conductor = conductor;

    this->elf = new ElfMap(executable);
    auto mainModule = conductor->parseExecutable(elf);
    mainModule->getLibrary()->setResolvedPath(executable);

    findEntryPointFunction();

    if(injectEgalito) {
#ifdef EGALITO_PATH
        //const char *path = "/home/dwk/project/egalito/egalito-spec-setup/src/libegalito.so";
        const char *path = EGALITO_PATH;
#else
        const char *name = "/libegalito.so";
        char path[PATH_MAX];
        auto sz = readlink("/proc/self/cwd", path, PATH_MAX);
        std::strcpy(&path[sz], name);
#endif
        LOG(1, "egalito is at " << path);
        this->egalito = new ElfMap(path);
        auto egalitoModule = conductor->parseEgalito(egalito);
        egalitoModule->getLibrary()->setResolvedPath(path);
        LoaderEmulator::getInstance().setup(conductor);
    }

    if(withSharedLibs) {
        conductor->parseLibraries();
    }

    if(withSharedLibs) {
        conductor->resolvePLTLinks();
    }
    conductor->resolveData();
    conductor->resolveTLSLinks();
    conductor->resolveVTables();

#ifndef RELEASE_BUILD
    conductor->check();
#endif

    // At this point, all the effort for resolving the links should have
    // been performed (except for special cases)

    int i = 0;
    for(auto module : CIter::modules(conductor->getProgram())) {
        auto elfMap = module->getElfSpace()->getElfMap();
        // this address has to be low enough to express negative offset in
        // jump table slots (to represent an index)
        if(setBaseAddress(elfMap, 0x10000000 + i*0x1000000)) {
            i ++;
        }
    }

    ClearSpatialPass clearSpatial;
    for(auto module : CIter::modules(conductor->getProgram())) {
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

Sandbox *ConductorSetup::makeLoaderSandbox() {
    auto backing = MemoryBacking(sandboxBase, 10 * 0x1000 * 0x1000);
    sandboxBase += 10 * 0x1000 * 0x1000;
#ifdef LINUX_KERNEL_MODE
    auto sandbox = new SandboxImpl<MemoryBacking,
        WatermarkAllocator<MemoryBacking>>(backing);
#else
    auto sandbox = new SandboxImpl<MemoryBacking,
        AlignedWatermarkAllocator<MemoryBacking>>(backing);
#endif
    //this->sandbox = sandbox;
    return sandbox;
}

ShufflingSandbox *ConductorSetup::makeShufflingSandbox() {
    auto backing = MemoryBacking(sandboxBase, 1 * 0x1000 * 0x1000);
    sandboxBase += 2 * 0x1000 * 0x1000;
    auto sandbox1 = new SandboxImpl<MemoryBacking,
        WatermarkAllocator<MemoryBacking>>(backing);

    auto backing2 = MemoryBacking(sandboxBase, 1 * 0x1000 * 0x1000);
    sandboxBase += 2 * 0x1000 * 0x1000;
    auto sandbox2 = new SandboxImpl<MemoryBacking,
        WatermarkAllocator<MemoryBacking>>(backing2);
    return new DualSandbox<SandboxImpl<MemoryBacking,
        WatermarkAllocator<MemoryBacking>>>(sandbox1, sandbox2);
}

Sandbox *ConductorSetup::makeFileSandbox(const char *outputFile) {
    // auto backing = ExeBacking(conductor->getMainSpace(), outputFile);
    // this->sandbox = new SandboxImpl<ExeBacking,
    //     WatermarkAllocator<ExeBacking>>(backing);
    //auto backing = ObjBacking(conductor->getMainSpace(), outputFile);
    //return new SandboxImpl<ObjBacking, WatermarkAllocator<ObjBacking>>(backing);
    auto backing = AnyGenerateBacking(conductor->getProgram()->getMain(), outputFile);
    return new SandboxImpl<AnyGenerateBacking, WatermarkAllocator<AnyGenerateBacking>>(backing);
}

void ConductorSetup::moveCode(Sandbox *sandbox, bool useDisps) {
    // 1. assign new addresses to all code
    moveCodeAssignAddresses(sandbox, useDisps);

    // 2. copy code to the new addresses
    copyCodeToNewAddresses(sandbox, useDisps);

    // 3. make code executable, or change permissions
    moveCodeMakeExecutable(sandbox);
}

void ConductorSetup::moveCodeAssignAddresses(Sandbox *sandbox, bool useDisps) {
    Generator generator(useDisps);

    for(auto module : CIter::modules(conductor->getProgram())) {
        generator.pickAddressesInSandbox(module, sandbox);
    }
}

void ConductorSetup::copyCodeToNewAddresses(Sandbox *sandbox, bool useDisps) {
    Generator generator(useDisps);

    for(auto module : CIter::modules(conductor->getProgram())) {
        generator.copyCodeToSandbox(module, sandbox);
    }
}

void ConductorSetup::moveCodeMakeExecutable(Sandbox *sandbox) {
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
