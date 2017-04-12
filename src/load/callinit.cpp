#include "callinit.h"
#include "elf/elfspace.h"
#include "chunk/concrete.h"
#include "log/log.h"

void CallInit::callInitFunctions(ElfSpace *space) {
    auto elf = space->getElfMap();
    auto module = space->getModule();
    auto init_array = (elf->findSection(".init_array"))->getHeader();
    if(init_array) {
        unsigned long *array = (elf->getSectionReadPtr<unsigned long *>(".init_array"));
        for(size_t i = 0; i < init_array->sh_size / sizeof(*array); i ++) {
            address_t func = elf->getBaseAddress() + array[i];
            LOG(1, "init_array function 0x" << std::hex << func);

            auto found = space->getSymbolList()->find(array[i]);
            if(found) {
                auto chunk = CIter::named(module->getFunctionList())
                    ->find(found->getName());
                LOG(1, "invoking init function " << chunk->getName());
                // then, we should actually call this...
                ((void (*)())chunk->getAddress())();
            }
        }
    }
}
