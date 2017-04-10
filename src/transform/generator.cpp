#include <iostream>  // for std::cout.flush()
#include <iomanip>
#include <cstdio>  // for std::fflush
#include "generator.h"
#include "operation/mutator.h"
#include "instr/semantic.h"

#undef DEBUG_GROUP
#define DEBUG_GROUP dassign
#include "log/log.h"

#if 0
Sandbox *Generator::makeSandbox() {
    auto backing = MemoryBacking(10 * 0x1000 * 0x1000);
    return new SandboxImpl<MemoryBacking,
        WatermarkAllocator<MemoryBacking>>(backing);
}
#endif

void Generator::pickAddressesInSandbox(Module *module, Sandbox *sandbox) {
    for(auto f : CIter::functions(module)) {
        //auto slot = sandbox->allocate(std::max((size_t)0x1000, f->getSize()));
        auto slot = sandbox->allocate(f->getSize());
        LOG(2, "    alloc 0x" << std::hex << slot.getAddress()
            << " for [" << f->getName()
            << "] size " << std::dec << f->getSize());
        //f->getPosition()->set(slot.getAddress());
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
}

void Generator::copyCodeToSandbox(Module *module, Sandbox *sandbox) {
    LOG(1, "Copying code into sandbox");
    for(auto f : CIter::functions(module)) {
        char *output = reinterpret_cast<char *>(f->getAddress());
        LOG(2, "    writing out [" << f->getName() << "] at 0x" << std::hex << f->getAddress());
        for(auto b : CIter::children(f)) {
            for(auto i : CIter::children(b)) {
                i->getSemantic()->writeTo(output);
                output += i->getSemantic()->getSize();
            }
        }
    }

    if(module->getPLTList()) {
        LOG(1, "Copying PLT entries into sandbox");
        for(auto plt : CIter::plts(module)) {
            char *output = reinterpret_cast<char *>(plt->getAddress());
            plt->writeTo(output);
        }
    }
}

void Generator::jumpToSandbox(Sandbox *sandbox, Module *module,
    const char *function) {

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
