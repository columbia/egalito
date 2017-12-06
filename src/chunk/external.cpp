#include "external.h"
#include "concrete.h"
#include "operation/find2.h"
#include "log/log.h"

ExternalSymbol *ExternalSymbolFactory::makeExternalSymbol(Symbol *symbol) {
    return makeExternalSymbol(symbol->getName(),
        symbol->getType(), symbol->getBind(), nullptr);
}

ExternalSymbol *ExternalSymbolFactory::makeExternalSymbol(
    const std::string &name, Symbol::SymbolType type, Symbol::BindingType bind,
    Chunk *resolved) {

    auto data = makeExternalSymbolList();
    // !!! linear search
    for(auto xs : CIter::children(data)) {
        if(xs->getName() == name && xs->getType() == type
            && xs->getBind() == bind) {

            return xs;
        }
    }

    auto xSymbol = new ExternalSymbol(name, type, bind);
    xSymbol->setResolved(resolved);
    data->addExternalSymbol(xSymbol);
    return xSymbol;
}

ExternalSymbolList *ExternalSymbolFactory::makeExternalSymbolList() {
    if(!module->getExternalSymbolList()) {
        module->setExternalSymbolList(new ExternalSymbolList());
    }
    return module->getExternalSymbolList();
}

void ExternalSymbolFactory::resolveAllSymbols(Program *program) {
    for(auto lib : CIter::children(program->getLibraryList())) {
        if(lib->getModule() == nullptr) {
            LOG(1, "WARNING: resolving external symbols but Module \""
                << lib->getName() << "\" is not loaded");
        }
    }

    for(auto xSymbol : CIter::children(module->getExternalSymbolList())) {
        resolveOneSymbol(program, xSymbol);
    }
}

void ExternalSymbolFactory::resolveOneSymbol(Program *program,
    ExternalSymbol *xSymbol) {

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
            << xSymbol->getName() << "\" of type " << xSymbol->getType());
    }
}
