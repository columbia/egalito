#include "findinitfuncs.h"
#include "chunk/module.h"
#include "chunk/initfunction.h"
#include "operation/find2.h"
#include "log/log.h"

void FindInitFuncs::visit(Module *module) {
    auto initFunctionList = new InitFunctionList(true);
    auto finiFunctionList = new InitFunctionList(false);
    for(auto region : CIter::regions(module)) {
        for(auto section : CIter::children(region)) {
            //LOG(1, "Examing Section: " << section->getName());
            if(section->getType() == DataSection::TYPE_INIT_ARRAY) {
                for(auto var : CIter::children(section)) {
                    if(!var->getDest() || !var->getDest()->getTarget()) {
                        LOG(0, "Error: .init_array target function not known");
                        continue;
                    }
                    auto initFunction = new InitFunction(true, var);
                    // TODO: Use a position type to track dataregion address.
                    initFunction->setPosition(new AbsolutePosition(var->getAddress()));
                    initFunctionList->getChildren()->add(initFunction);
                    initFunction->setParent(initFunctionList);
                }
            }
            if(section->getType() == DataSection::TYPE_FINI_ARRAY) {
                for(auto var : CIter::children(section)) {
                    if(!var->getDest() || !var->getDest()->getTarget()) {
                        LOG(0, "Error: .fini_array target function not known");
                        continue;
                    }
                    auto finiFunction = new InitFunction(false, var);
                    finiFunction->setPosition(new AbsolutePosition(var->getAddress()));
                    finiFunctionList->getChildren()->add(finiFunction);
                    finiFunction->setParent(finiFunctionList);
                }
            }
            // .init, .fini not handled
            if(section->getName() == ".init") {
                auto program = dynamic_cast<Program *>(module->getParent());
                auto func = ChunkFind2(program).findFunctionContainingInModule(section->getAddress(), module);
                if(func) {
                    auto initFunction = new InitFunction(true, func, true);
                    initFunctionList->getChildren()->getIterable()->add(initFunction);
                    initFunctionList->setSpecialCase(initFunction);
                }
            }
            if(section->getName() == ".fini") {
                auto program = dynamic_cast<Program *>(module->getParent());
                auto func = ChunkFind2(program).findFunctionContainingInModule(section->getAddress(), module);
                if(func) {
                    auto finiFunction = new InitFunction(false, func, true);
                    finiFunctionList->getChildren()->getIterable()->add(finiFunction);
                    finiFunctionList->setSpecialCase(finiFunction);
                }
            }
        }
    }

    module->getChildren()->add(initFunctionList);
    module->setInitFunctionList(initFunctionList);
    initFunctionList->setParent(module);

    module->getChildren()->add(finiFunctionList);
    module->setFiniFunctionList(finiFunctionList);
    finiFunctionList->setParent(module);

    LOG(1, "Init functions in [" << module->getName() << "]: " 
        << initFunctionList->getChildren()->genericGetSize());
    LOG(1, "Fini functions in [" << module->getName() << "]: " 
        << finiFunctionList->getChildren()->genericGetSize());
}
