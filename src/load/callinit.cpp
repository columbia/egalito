#include "callinit.h"
#include "emulator.h"
#include "elf/elfspace.h"
#include "chunk/concrete.h"
#include "operation/find2.h"
#include "log/log.h"

#define EGALITO_INIT_ARRAY_SZ   16
address_t egalito_init_array[EGALITO_INIT_ARRAY_SZ];
static size_t init_index = 3;

void CallInit::makeInitArray(ElfSpace *space, int argc, char **argv,
    char **envp) {

    if(!space) return;

    auto elf = space->getElfMap();
    auto module = space->getModule();

    auto _init = ChunkFind2().findFunctionInModule("_init", module);
    if(_init) {
        egalito_init_array[init_index++] = _init->getAddress();
    }

    auto init_array = elf->findSection(".init_array");
    if(init_array) {
        unsigned long *array = elf->getSectionReadPtr<unsigned long *>(
            init_array);
        for(size_t i = 0;
            i < init_array->getHeader()->sh_size / sizeof(*array);
            i ++) {

            auto found = space->getSymbolList()->find(array[i]);
            if(found) {
                auto chunk = CIter::named(module->getFunctionList())
                    ->find(found->getName());
                egalito_init_array[init_index++] = chunk->getAddress();
            }
        }
    }

    egalito_init_array[0] = (address_t)argc;
    egalito_init_array[1] = (address_t)argv;
    egalito_init_array[2] = (address_t)envp;
}

extern "C"
void egalito_callInit(void) {
    int argc = (int)egalito_init_array[0];
    char **argv = (char **)egalito_init_array[1];
    char **envp = (char **)egalito_init_array[2];

    typedef void (*init_t)(int, char **, char **);
    for(size_t i = 3; i < init_index; i++) {
        init_t f = (init_t)egalito_init_array[i];
        f(argc, argv, envp);
    }
}

