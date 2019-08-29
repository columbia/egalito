#include <iostream>  // for std::cout.flush()
#include <iomanip>
#include <cstdio>  // for std::fflush
#include <cstring>
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

// Instantiated for Function, PLTTrampoline
template <typename ChunkType>
class GeneratorHelper {
public:
    void assignAddress(ChunkType *chunk, Slot slot);
    void copyToSandbox(ChunkType *chunk, Sandbox *sandbox);
private:
    void addPaddingBytes(ChunkType *chunk, Sandbox *sandbox);
};

template <typename ChunkType>
void GeneratorHelper<ChunkType>::assignAddress(ChunkType *chunk, Slot slot) {
#if 0
    ChunkMutator(chunk).setPosition(slot.getAddress());
#else
    if(auto v = chunk->getAssignedPosition()) {
        v->set(slot);
    }
    else {
        chunk->setAssignedPosition(new SlotPosition(slot));
    }
#endif
}

template <>
void GeneratorHelper<Function>::copyToSandbox(Function *function, Sandbox *sandbox) {
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
                if(true /*useDisps*/) {
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
    addPaddingBytes(function, sandbox);
}

template <>
void GeneratorHelper<PLTTrampoline>::copyToSandbox(PLTTrampoline *trampoline, Sandbox *sandbox) {
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
        //size_t expectedSize = backing->getBuffer().length() + PLTList::getPLTTrampolineSize();
        size_t expectedSize = backing->getBuffer().length() + trampoline->getSize();
        trampoline->writeTo(backing->getBuffer());
#if 1
        size_t actualSize = backing->getBuffer().length();
        if (actualSize > expectedSize) {
            LOG(0, "Writing too much data to PLT entry!!!!!");
        } else {
            backing->getBuffer().append(expectedSize - actualSize, (char)0xf4);
        }
#endif
    }
    addPaddingBytes(trampoline, sandbox);
}

template <typename ChunkType>
void GeneratorHelper<ChunkType>::addPaddingBytes(ChunkType *chunk, Sandbox *sandbox) {
    auto assignedSize = chunk->getAssignedPosition()->getAssignedSize();
    if(assignedSize > chunk->getSize()) {
        // Add appropriate number of NOP bytes
        auto padding = assignedSize - chunk->getSize();
        if(sandbox->supportsDirectWrites()) {
            char *output = reinterpret_cast<char *>(chunk->getAddress());
#ifdef ARCH_X86_64
            std::memset(output + chunk->getSize(), 0x90, padding);
#else
            // Should use platform-specific NOP here
            std::memset(output + chunk->getSize(), 0x0, padding);
#endif
        }
        else {
            auto backing = static_cast<MemoryBufferBacking *>(sandbox->getBacking());
#ifdef ARCH_X86_64
            backing->getBuffer().append(padding, static_cast<char>(0x90));
#else
            // Should use platform-specific NOP here
            backing->getBuffer().append(padding, static_cast<char>(0x0));
#endif
        }
    }
    else if(assignedSize < chunk->getSize()) {
        LOG(0, "ERROR: assigned size " << std::dec << assignedSize
            << " is too small to store chunk ["
            << chunk->getName() << "] of size " << chunk->getSize());
    }
}

void Generator::assignAddresses(Program *program) {
    for(auto module : CIter::modules(program)) {
        assignAddresses(module);
    }
}

void Generator::generateCode(Program *program, const std::vector<Function *> &order) {
    for(auto module : CIter::modules(program)) {
        generateCode(module, order);
    }
}

void Generator::assignAddresses(Program *program, const std::vector<Function *> &order) {
    for(auto module : CIter::modules(program)) {
        assignAddresses(module, order);
    }
}

void Generator::generateCode(Program *program) {
    for(auto module : CIter::modules(program)) {
        generateCode(module);
    }
}

std::vector<Function *> Generator::pickFunctionOrder(Module *module) {
    std::vector<Function *> order;

    Function *startup_64 = nullptr;
#ifdef LINUX_KERNEL_MODE
    startup_64 = ChunkFind2().findFunctionInModule("startup_64", module);
#endif

#if 0  // order functions according to their symbol name
    order.push_back(startup_64);
    for(auto f : CIter::functions(module)) {
        if(f == startup_64) continue;
        order.push_back(f);
    }
#else  // order functions according to original order
    for(auto f : CIter::functions(module)) {
        order.push_back(f);
    }

    std::sort(order.begin(), order.end(), [startup_64] (Function *a, Function *b) {
#ifdef LINUX_KERNEL_MODE
        // always put startup_64 first
        if(a == startup_64) return true;
        if(b == startup_64) return false;
#endif
        return a->getAddress() < b->getAddress();
    });
#endif

    return order;
}

void Generator::assignAddresses(Module *module) {
    auto order = pickFunctionOrder(module);
    for(auto f : order) {
        auto slot = sandbox->allocate(f->getSize());
        LOG(2, "    alloc 0x" << std::hex << slot.getAddress()
            << " for [" << f->getName()
            << "] size " << std::dec << f->getSize());
        GeneratorHelper<Function>().assignAddress(f, slot);
    }

    if(module->getPLTList()) {
        // these don't have to be contiguous
        //const size_t pltSize = PLTList::getPLTTrampolineSize();
        for(auto plt : CIter::plts(module)) {
            auto slot = sandbox->allocate(plt->getSize());
            LOG(2, "    alloc 0x" << std::hex << slot.getAddress()
                << " for [" << plt->getName()
                << "] size " << std::dec << plt->getSize());
            GeneratorHelper<PLTTrampoline>().assignAddress(plt, slot);
        }
    }

    ClearSpatialPass clearSpatial;
    module->accept(&clearSpatial);
}

void Generator::generateCode(Module *module) {
    LOG(1, "Copying code into sandbox");
    auto order = pickFunctionOrder(module);
    for(auto f : order) {
        LOG(2, "    writing out [" << f->getName() << "] at 0x"
            << std::hex << f->getAddress());

        GeneratorHelper<Function>().copyToSandbox(f, sandbox);
    }

    if(module->getPLTList()) {
        LOG(1, "Copying PLT entries into sandbox");
        for(auto plt : CIter::plts(module)) {
            GeneratorHelper<PLTTrampoline>().copyToSandbox(plt, sandbox);
        }
    }
}

void Generator::assignAddresses(Module *module, const std::vector<Function *> &order) {
    for(auto f : order) {
        auto slot = sandbox->allocate(f->getSize());
        LOG(2, "    alloc 0x" << std::hex << slot.getAddress()
            << " for [" << f->getName()
            << "] size " << std::dec << f->getSize());
        GeneratorHelper<Function>().assignAddress(f, slot);
    }

    if(module->getPLTList()) {
        // these don't have to be contiguous
        //const size_t pltSize = PLTList::getPLTTrampolineSize();
        for(auto plt : CIter::plts(module)) {
            auto slot = sandbox->allocate(plt->getSize());
            LOG(2, "    alloc 0x" << std::hex << slot.getAddress()
                << " for [" << plt->getName()
                << "] size " << std::dec << plt->getSize());
            GeneratorHelper<PLTTrampoline>().assignAddress(plt, slot);
        }
    }

    ClearSpatialPass clearSpatial;
    module->accept(&clearSpatial);
}

void Generator::generateCode(Module *module, const std::vector<Function *> &order) {
    LOG(1, "Copying code into sandbox");
    for(auto f : order) {
        LOG(2, "    writing out [" << f->getName() << "] at 0x"
            << std::hex << f->getAddress());

        GeneratorHelper<Function>().copyToSandbox(f, sandbox);
    }

    if(module->getPLTList()) {
        LOG(1, "Copying PLT entries into sandbox");
        for(auto plt : CIter::plts(module)) {
            GeneratorHelper<PLTTrampoline>().copyToSandbox(plt, sandbox);
        }
    }
}

void Generator::assignAddressForFunction(Function *function) {
    auto slot = sandbox->allocate(function->getSize());
    LOG(1, "Assigning address to 0x" << std::hex << slot.getAddress()
        << " for [" << function->getName()
        << "] size " << std::dec << function->getSize());
    GeneratorHelper<Function>().assignAddress(function, slot);
}

void Generator::generateCodeForFunction(Function *function) {
    LOG(1, "Copying function [" << function->getName() << "] at 0x"
        << std::hex << function->getAddress());
    GeneratorHelper<Function>().copyToSandbox(function, sandbox);
}

// These two functions are only used during JIT-Shuffling
void Generator::pickFunctionAddressInSandbox(Function *function) {
    auto slot = sandbox->allocate(function->getSize());
    //ChunkMutator(function).setPosition(slot.getAddress());
    PositionManager::setAddress(function, slot.getAddress());
}
void Generator::pickPLTAddressInSandbox(PLTTrampoline *trampoline) {
    //auto slot = sandbox->allocate(PLTList::getPLTTrampolineSize());
    auto slot = sandbox->allocate(trampoline->getSize());
    //ChunkMutator(trampoline).setPosition(slot.getAddress());
    PositionManager::setAddress(trampoline, slot.getAddress());
}

void Generator::assignAndGenerate(Function *function) {
    pickFunctionAddressInSandbox(function);
    GeneratorHelper<Function>().copyToSandbox(function, sandbox);
}

void Generator::assignAndGenerate(PLTTrampoline *trampoline) {
    pickPLTAddressInSandbox(trampoline);
    GeneratorHelper<PLTTrampoline>().copyToSandbox(trampoline, sandbox);
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
