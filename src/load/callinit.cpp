#include <cassert>
#include "callinit.h"
#include "conductor/conductor.h"
#include "elf/elfspace.h"
#include "chunk/concrete.h"
#include "chunk/gstable.h"
#include "operation/find2.h"
#include "log/log.h"

#define EGALITO_INIT_ARRAY_SZ   16
address_t egalito_init_array[EGALITO_INIT_ARRAY_SZ];

void CallInit::makeInitArray(ElfSpace *space, int argc, char **argv,
    char **envp, GSTable *gsTable) {

    egalito_init_array[1] = (address_t)argc;
    egalito_init_array[2] = (address_t)argv;
    egalito_init_array[3] = (address_t)envp;
    size_t init_index = 4;

    if(!space) return;

    auto elf = space->getElfMap();
    auto module = space->getModule();

    auto _init = ChunkFind2().findFunctionInModule("_init", module);
    if(_init) {
        if(gsTable) {
            auto gsEntry = gsTable->makeEntryFor(_init);
            egalito_init_array[init_index++] = gsEntry->getOffset();
        }
        else {
            egalito_init_array[init_index++] = _init->getAddress();
        }
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
                if(gsTable) {
                    auto gsEntry = gsTable->makeEntryFor(chunk);
                    egalito_init_array[init_index++] = gsEntry->getOffset();
                }
                else {
                    egalito_init_array[init_index++] = chunk->getAddress();
                }
            }
        }
    }
    assert(init_index + 1 <= EGALITO_INIT_ARRAY_SZ);
    egalito_init_array[0] = init_index - 1;
}

auto CallInit::getStart2(Conductor *conductor) -> Start2Type {
    auto egalito = conductor->getProgram()->getEgalito();
    auto addr = ChunkFind2(conductor).findFunctionInModule("_start2", egalito)
        ->getAddress();
    return reinterpret_cast<Start2Type>(addr);
}

extern "C"
void egalito_callInit(void) {
    size_t init_index = (size_t)egalito_init_array[0];
    int argc = (int)egalito_init_array[1];
    char **argv = (char **)egalito_init_array[2];
    char **envp = (char **)egalito_init_array[3];

    typedef void (*init_t)(int, char **, char **);
    for(size_t i = 4; i < init_index; i++) {
        init_t f = (init_t)egalito_init_array[i];
        f(argc, argv, envp);
    }
}

