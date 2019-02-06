#include "elf/symbol.h"
#include "elf/elfspace.h"
#include "chunk/dataregion.h"

#include "collectglobals.h"

#include "log/log.h"

void CollectGlobalsPass::visit(Module *module) {
    auto elfspace = module->getElfSpace();
    if(!elfspace) return;

    auto dynsyms = elfspace->getDynamicSymbolList();

    for(auto symbol : (*dynsyms)) {
        if(symbol->getType() != Symbol::TYPE_OBJECT) continue;

        address_t address = symbol->getAddress();
        DataSection *section =
            module->getDataRegionList()->findDataSectionContaining(address);

        if(!section) continue;

        LOG(10, "global variable [" << (symbol->getName()) << "] found");

        GlobalVariable::createDynamic(section, address, symbol);
    }
}
