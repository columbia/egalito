#include <iostream>  // for std::cout.flush()
#include <iomanip>
#include <cstdio>  // for std::fflush
#include "generator.h"
#include "chunk/cache.h"
#include "operation/mutator.h"
#include "operation/find2.h"
#include "pass/clearspatial.h"
#include "instr/semantic.h"
#include "instr/writer.h"

#undef DEBUG_GROUP
#define DEBUG_GROUP dassign
#include "log/log.h"
#include "log/temp.h"

#include "config.h"

void Generator::assignAddresses(Program *program) {
    for(auto module : CIter::modules(program)) {
        assignAddresses(module);
    }
}

void Generator::generateCode(Program *program) {
    for(auto module : CIter::modules(program)) {
        generateCode(module);
    }
}

void Generator::assignAddresses(Module *module) {
#ifdef LINUX_KERNEL_MODE
    Function *startup_64 = ChunkFind2()
        .findFunctionInModule("startup_64", module);
    if(startup_64) {
        auto slot = sandbox->allocate(startup_64->getSize());
        LOG(2, "    alloc 0x" << std::hex << slot.getAddress()
            << " for [" << startup_64->getName()
            << "] size " << std::dec << startup_64->getSize());
        ChunkMutator(startup_64).setPosition(slot.getAddress());
    }
#endif

    for(auto f : CIter::functions(module)) {
#ifdef LINUX_KERNEL_MODE
        if(f == startup_64) continue;
#endif
        //auto slot = sandbox->allocate(std::max((size_t)0x1000, f->getSize()));
        auto slot = sandbox->allocate(f->getSize());
        LOG(2, "    alloc 0x" << std::hex << slot.getAddress()
            << " for [" << f->getName()
            << "] size " << std::dec << f->getSize());
        ChunkMutator(f).setPosition(slot.getAddress());
    }

    if(module->getPLTList()) {
        // these don't have to be contiguous
        const size_t pltSize = PLTList::getPLTTrampolineSize();
        for(auto plt : CIter::plts(module)) {
            auto slot = sandbox->allocate(pltSize);
            LOG(2, "    alloc 0x" << std::hex << slot.getAddress()
                << " for [" << plt->getName()
                << "] size " << std::dec << pltSize);
            ChunkMutator(plt).setPosition(slot.getAddress());
        }
    }

    ClearSpatialPass clearSpatial;
    module->accept(&clearSpatial);
}

void Generator::generateCode(Module *module) {
#ifdef LINUX_KERNEL_MODE
    Function *startup_64 = ChunkFind2()
        .findFunctionInModule("startup_64", module);
    if(startup_64) {
        copyFunctionToSandbox(startup_64);
    }
#endif

    LOG(1, "Copying code into sandbox");
    for(auto f : CIter::functions(module)) {
#ifdef LINUX_KERNEL_MODE
        if(f == startup_64) continue;
#endif
        LOG(2, "    writing out [" << f->getName() << "] at 0x"
            << std::hex << f->getAddress());

        copyFunctionToSandbox(f);
    }

    if(module->getPLTList()) {
        LOG(1, "Copying PLT entries into sandbox");
        for(auto plt : CIter::plts(module)) {
            copyPLTToSandbox(plt);
        }
    }
}

void Generator::copyFunctionToSandbox(Function *function) {
    if(sandbox->supportsDirectWrites()) {
        char *output = reinterpret_cast<char *>(function->getAddress());
        if(auto cache = function->getCache()) {
            //LOG(0, "generating with Cache: " << function->getName());
            cache->copyAndFix(output);
            return;
        }
        for(auto b : CIter::children(function)) {
            for(auto i : CIter::children(b)) {
                LOG(10, " at " << std::hex << i->getAddress());
                if(useDisps) {
                    InstrWriterCString writer(output);
                    i->getSemantic()->accept(&writer);
                }
                else {
                    InstrWriterForObjectFile writer(output);
                    i->getSemantic()->accept(&writer);
                }
                output += i->getSemantic()->getSize();
            }
        }
    }
    else {
        auto backing = static_cast<MemoryBufferBacking *>(sandbox->getBacking());
        InstrWriterCppString writer(backing->getBuffer());
        for(auto b : CIter::children(function)) {
            for(auto i : CIter::children(b)) {
                i->getSemantic()->accept(&writer);
            }
        }
    }
}

void Generator::copyPLTToSandbox(PLTTrampoline *trampoline) {
    if(sandbox->supportsDirectWrites()) {
        char *output = reinterpret_cast<char *>(trampoline->getAddress());
        if(auto cache = trampoline->getCache()) {
            //LOG(0, "generating with Cache: " << function->getName());
            cache->copyAndFix(output);
            return;
        }
        trampoline->writeTo(output);
    }
    else {
        auto backing = static_cast<MemoryBufferBacking *>(sandbox->getBacking());
        size_t expectedSize = backing->getBuffer().length() + PLTList::getPLTTrampolineSize();
        trampoline->writeTo(backing->getBuffer());
        size_t actualSize = backing->getBuffer().length();
        if (actualSize > expectedSize) {
            LOG(0, "Writing too much data to PLT entry!!!!!");
        } else { 
            backing->getBuffer().append(expectedSize - actualSize, (char)0xf4);
        }
    }
}

// These two functions are only used during JIT-Shuffling
void Generator::pickFunctionAddressInSandbox(Function *function) {
    auto slot = sandbox->allocate(function->getSize());
    //ChunkMutator(function).setPosition(slot.getAddress());
    PositionManager::setAddress(function, slot.getAddress());
}
void Generator::pickPLTAddressInSandbox(PLTTrampoline *trampoline) {
    auto slot = sandbox->allocate(PLTList::getPLTTrampolineSize());
    //ChunkMutator(trampoline).setPosition(slot.getAddress());
    PositionManager::setAddress(trampoline, slot.getAddress());
}

void Generator::assignAndGenerate(Function *function) {
    pickFunctionAddressInSandbox(function);
    copyFunctionToSandbox(function);
}

void Generator::assignAndGenerate(PLTTrampoline *trampoline) {
    pickPLTAddressInSandbox(trampoline);
    copyPLTToSandbox(trampoline);
}

void Generator::jumpToSandbox(Module *module, const char *function) {
    auto f = CIter::named(module->getFunctionList())->find(function);
    if(!f) return;

    LOG(1, "jumping to [" << function << "] at 0x"
        << std::hex << f->getAddress());
    int (*mainp)(int, char **) = (int (*)(int, char **))f->getAddress();

    int argc = 1;
    char *argv[] = {(char *)"/dev/null", NULL};

    std::cout.flush();
    std::fflush(stdout);
    mainp(argc, argv);

    LOG(1, "RETURNED from target");
}
