#include <cassert>
#include <cstring>
#include "callinit.h"
#include "conductor/conductor.h"
#include "elf/elfspace.h"
#include "chunk/concrete.h"
#include "chunk/gstable.h"
#include "operation/find2.h"
#include "util/feature.h"
#include "log/log.h"
#include "log/temp.h"

#define EGALITO_INIT_ARRAY_SZ   512

address_t egalito_init_array[EGALITO_INIT_ARRAY_SZ] __attribute__((weak));

bool egalito_init_done __attribute__((weak));
extern "C" void egalito_jit_gs_setup();

extern "C"
void egalito_runtime_init(void) {

    if(isFeatureEnabled("EGALITO_USE_GS")) {
        egalito_jit_gs_setup();
    }
    egalito_init_done = true;
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

void CallInit::makeInitArray(Program *program, int argc, char **argv,
    char **envp, GSTable *gsTable) {

    egalito_init_array[1] = (address_t)argc;
    egalito_init_array[2] = (address_t)argv;
    egalito_init_array[3] = (address_t)envp;
    size_t init_index = 4;

    // This is just a heuristics.
    // libpthread needs other libraries but has DF_1_INITFIRST flag set.
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

    //TemporaryLogLevel tll("load", 10);
    IF_LOG(10) {
        LOG(1, "constructors must be called in this order");
        for(auto module : order) {
            LOG(1, "    " << module->getName());
        }
    }

    for(auto module : order) {
        LOG(10, "module " << module->getName());

        auto _init = ChunkFind2().findFunctionInModule("_init", module);
        if(_init) {
            LOG(10, "egalito_init_array[" << init_index << "] _init");
            if(gsTable) {
                auto gsEntry = gsTable->makeJITEntryFor(_init);
                egalito_init_array[init_index++] = gsEntry->getOffset();
            }
            else {
                egalito_init_array[init_index++] = _init->getAddress();
            }
        }

        // we should look in memory mapped region to get relocated pointers
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
                            LOG(10, "egalito_init_array[" << init_index
                                << "] " << gsEntry->getTarget()->getName());
                            egalito_init_array[init_index++]
                                = gsEntry->getOffset();
                        }
                        else {
                            auto chunk
                                = CIter::spatial(module->getFunctionList())
                                ->findContaining(array[i]);
                            assert(chunk);
                            LOG(10, "egalito_init_array[" << init_index
                                << "] " << chunk->getName());
                            egalito_init_array[init_index++]
                                = chunk->getAddress();
                        }
                    }
                }
            }
        }
    }

    auto chunk = ChunkFind2().findFunctionInModule(
        "egalito_runtime_init", program->getEgalito());
    assert(chunk);
    if(gsTable) {
        auto gsEntry = gsTable->makeJITEntryFor(chunk);
        egalito_init_array[init_index++] = gsEntry->getOffset();
    }
    else {
        egalito_init_array[init_index++] = chunk->getAddress();
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

