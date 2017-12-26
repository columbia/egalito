#include <cassert>
#include "callinit.h"
#include "conductor/conductor.h"
#include "elf/elfspace.h"
#include "chunk/concrete.h"
#include "chunk/gstable.h"
#include "operation/find2.h"
#include "log/log.h"

#define EGALITO_INIT_ARRAY_SZ   256
address_t egalito_init_array[EGALITO_INIT_ARRAY_SZ];

void CallInit::makeInitArray(Program *program, int argc, char **argv,
    char **envp, GSTable *gsTable) {

    egalito_init_array[1] = (address_t)argc;
    egalito_init_array[2] = (address_t)argv;
    egalito_init_array[3] = (address_t)envp;
    size_t init_index = 4;

    // This is just a heuristics. For example of an exception, libpthread
    // needs other libraries but has DF_1_INITFIRST flag set.
    std::vector<Module *> order;
    std::set<Library *> met;
    for(auto module : CIter::modules(program)) {
        if(module->getName() == "module-libpthread.so.0") {
            order.push_back(module);
            met.insert(module->getLibrary());
        }
    }
    size_t size;
    do {
        size = met.size();
        for(auto module : CIter::modules(program)) {
            auto library = module->getLibrary();
            if(met.find(library) != met.end()) continue;
            bool allmet = true;
            for(auto dep : library->getDependencies()) {
                if(met.find(dep) == met.end()) {
                    allmet = false;
                    break;
                }
            }
            if(allmet) {
                order.push_back(module);
                met.insert(library);
            }
        }
    } while(size != met.size());

    for(auto module : CIter::modules(program)) {
        if(met.find(module->getLibrary()) == met.end()) {
            LOG(1, "library dependency not found for " << module->getName());
            order.push_back(module);
        }
    }

    LOG(1, "constructors must be called in this order");
    for(auto module : order) {
        LOG(1, "    " << module->getName());
    }

    for(auto module : order) {
        LOG(1, "module " << module->getName());
#if 0
        // libpthread constructors need actual emulation
        if(module->getName() == "module-libpthread.so.0") continue;
#endif

        auto _init = ChunkFind2().findFunctionInModule("_init", module);
        if(_init) {
            LOG(1, "adding _init to egalito_init_array");
            if(gsTable) {
                auto gsEntry = gsTable->makeEntryFor(_init);
                egalito_init_array[init_index++] = gsEntry->getOffset();
            }
            else {
                egalito_init_array[init_index++] = _init->getAddress();
            }
        }

        // we should look into the section in memory mapped region to get the
        // relocated pointers
        for(auto region : CIter::regions(module)) {
            for(auto section : CIter::children(region)) {
                if(section->getType() == DataSection::TYPE_INIT_ARRAY) {
                    address_t *array
                        = reinterpret_cast<address_t *>(section->getAddress());
                    size_t count = section->getSize() / sizeof(*array);
                    for(size_t i = 0; i < count; i++) {
                        if(gsTable) {
                            auto index = gsTable->offsetToIndex(array[i]);
                            auto gsEntry = gsTable->getAtIndex(index);
                            LOG(1, "adding "
                                << gsEntry->getRealTarget()->getName()
                                << " to egalito_init_array");
                            egalito_init_array[init_index++]
                                = gsEntry->getOffset();
                        }
                        else {
                            auto chunk
                                = CIter::spatial(module->getFunctionList())
                                ->findContaining(array[i]);
                            assert(chunk);
                            LOG(1, "adding " << chunk->getName()
                                << " to egalito_init_array");
                            egalito_init_array[init_index++]
                                = chunk->getAddress();
                        }
                    }
                }
            }
        }
    }
    assert(init_index + 1 <= EGALITO_INIT_ARRAY_SZ);
    egalito_init_array[0] = init_index;
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
