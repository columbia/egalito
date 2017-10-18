#include "callinit.h"
#include "emulator.h"
#include "elf/elfspace.h"
#include "chunk/concrete.h"
#include "operation/find2.h"
#include "log/log.h"

void CallInit::callInitFunctions(ElfSpace *space, char **argv) {
    auto elf = space->getElfMap();
    auto module = space->getModule();

    auto _init = ChunkFind2().findFunctionInModule("_init", module);
    if(_init) {
        auto argc = *((unsigned long *)argv - 1);
        auto envp = (char **) *(unsigned long *)
            LoaderEmulator::getInstance().findSymbol("__environ");

        LOG(1, "invoking init function " << _init->getName());
        // !!! we should actually call this in transformed code...
        ((void (*)(int, char **, char **))_init->getAddress())(argc, argv, envp);
    }

    auto init_array = elf->findSection(".init_array");
    if(init_array) {
        unsigned long *array = elf->getSectionReadPtr<unsigned long *>(init_array);
        for(size_t i = 0; i < init_array->getHeader()->sh_size / sizeof(*array); i ++) {
            address_t func = elf->getBaseAddress() + array[i];
            LOG(1, "init_array function 0x" << std::hex << func);

            auto found = space->getSymbolList()->find(array[i]);
            if(found) {
                auto chunk = CIter::named(module->getFunctionList())
                    ->find(found->getName());
                LOG(1, "invoking init function " << chunk->getName());
                // !!! we should actually call this from transformed code...
                //((void (*)())chunk->getAddress())();
                ((void (*)(int, char*, char*))chunk->getAddress())(0, nullptr, nullptr);
                // !!! call the init_array functions
            }
        }
    }
}
