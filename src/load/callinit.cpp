#include "callinit.h"
#include "elf/elfspace.h"
#include "chunk/concrete.h"
#include "log/log.h"

void CallInit::callInitFunctions(ElfSpace *space) {
    auto elf = space->getElfMap();
    auto module = space->getModule();
    auto init_array = static_cast<Elf64_Shdr *>(
        elf->findSectionHeader(".init_array"));
    if(init_array) {
        unsigned long *array = static_cast<unsigned long *>(
            elf->findSection(".init_array"));
        for(size_t i = 0; i < init_array->sh_size / sizeof(*array); i ++) {
            address_t func = elf->getBaseAddress() + array[i];
            LOG(1, "init_array function 0x" << std::hex << func);

            auto found = space->getSymbolList()->find(array[i]);
            if(found) {
                auto chunk = CIter::named(module->getFunctionList())
                    ->find(found->getName());
                LOG(1, "got chunk " << chunk->getName());
                // then, we should actually call this...
                ((void (*)())chunk->getAddress())();
            }
        }
    }
}
