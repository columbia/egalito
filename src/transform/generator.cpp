#include <iomanip>
#include "generator.h"
#include "log/log.h"

Sandbox *Generator::makeSandbox() {
    auto backing = MemoryBacking(10 * 0x1000 * 0x1000);
    return new SandboxImpl<MemoryBacking,
        WatermarkAllocator<MemoryBacking>>(backing);
}

void Generator::copyCodeToSandbox(ElfMap *elf, Module *module,
    Sandbox *sandbox) {

    LOG(1, "Copying code into sandbox");
    for(auto f : module->getChildren()->getIterable()->iterable()) {
        auto slot = sandbox->allocate(std::max((size_t)0x1000, f->getSize()));
        LOG(2, "    alloc 0x" << std::hex << slot.getAddress()
            << " for [" << f->getName()
            << "] size " << std::dec << f->getSize());
        f->getPosition()->set(slot.getAddress());
    }

    for(auto f : module->getChildren()->getIterable()->iterable()) {
        char *output = reinterpret_cast<char *>(f->getAddress());
        LOG(2, "    writing out [" << f->getName() << "] at 0x" << std::hex << f->getAddress());
        for(auto b : f->getChildren()->getIterable()->iterable()) {
            for(auto i : b->getChildren()->getIterable()->iterable()) {
                i->getSemantic()->writeTo(output);
                output += i->getSemantic()->getSize();
            }
        }
    }

    sandbox->finalize();
}

void Generator::jumpToSandbox(Sandbox *sandbox, Module *module) {
    // jump straight to main()
    if(!module->getChildren()->getNamed()) {
        module->getChildren()->createNamed();
    }

    auto f = module->getChildren()->getNamed()->find("main");
    if(!f) return;

    LOG(1, "main is at " << std::hex << f->getAddress());
    int (*mainp)(int, char **) = (int (*)(int, char **))f->getAddress();

    int argc = 1;
    char *argv[] = {(char *)"/dev/null", NULL};
    mainp(argc, argv);
}
