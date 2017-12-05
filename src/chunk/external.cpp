#include "external.h"
#include "program.h"
#include "function.h"
#include "operation/find2.h"
#include "log/log.h"

void ExternalData::registerModule(Module *module) {
    for(auto xm : externalModules) {
        if(xm->getName() == module->getName()) {
            xm->setResolved(module);
        }
    }
}

void ExternalData::resolveAllSymbols(Program *program) {
    for(auto xm : externalModules) {
        if(!xm->getResolved()) {
            LOG(1, "WARNING: resolving external symbols but Module \""
                << xm->getName() << "\" is not loaded");
        }
    }

    for(auto xSymbol : externalSymbols) {
        resolveOneSymbol(program, xSymbol);
    }
}

void ExternalData::resolveOneSymbol(Program *program, ExternalSymbol *xSymbol) {
    if(xSymbol->getType() == Symbol::TYPE_FUNC
        || xSymbol->getType() == Symbol::TYPE_IFUNC) {

        auto resolved = ChunkFind2(program)
            .findFunction(xSymbol->getName().c_str());
        xSymbol->setResolved(resolved);
        if(resolved && resolved->getParent()) {
            xSymbol->setResolvedModule(dynamic_cast<Module *>(
                resolved->getParent()->getParent()));
        }
    }
    else {
        LOG(1, "WARNING: don't know how to resolve external symbol \""
            << xSymbol << "\" of type " << xSymbol->getType());
    }
}

ExternalModule *ExternalFactory::makeExternalModule(const std::string &name) {
    auto data = makeExternalData();
    auto xModule = new ExternalModule(name);
    data->addExternalModule(xModule);
    return xModule;
}

ExternalSymbol *ExternalFactory::makeExternalSymbol(Symbol *symbol) {
    auto data = makeExternalData();
    auto xSymbol = new ExternalSymbol(
        symbol->getName(),
        symbol->getType(),
        symbol->getBind());
    data->addExternalSymbol(xSymbol);
    return xSymbol;
}

ExternalData *ExternalFactory::makeExternalData() {
    if(!module->getExternalData()) {
        module->setExternalData(new ExternalData());
    }
    return module->getExternalData();
}
