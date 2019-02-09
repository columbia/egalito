#include "elf/symbol.h"
#include "elf/elfspace.h"
#include "chunk/dataregion.h"

#include "collectglobals.h"

#include "log/log.h"

void CollectGlobalsPass::visit(Module *module) {
    auto elfspace = module->getElfSpace();
    if(!elfspace) return;

    auto syms = elfspace->getSymbolList();
    auto dynsyms = elfspace->getDynamicSymbolList();

    std::map<address_t, GlobalVariable *> variables;

    for(auto symbol : *syms) {
        if(symbol->getType() != Symbol::TYPE_OBJECT) continue;

        address_t address = symbol->getAddress();
        DataSection *section =
            module->getDataRegionList()->findDataSectionContaining(address);

        if(!section) continue;

        LOG(10, "symtab global variable [" << (symbol->getName()) << "] found");

        variables[address] =
            GlobalVariable::createSymtab(section, address, symbol);
    }

    for(auto symbol : *dynsyms) {
        if(symbol->getType() != Symbol::TYPE_OBJECT) continue;

        address_t address = symbol->getAddress();
        DataSection *section =
            module->getDataRegionList()->findDataSectionContaining(address);

        if(!section) continue;

        LOG(10, "dynsym global variable [" << (symbol->getName()) << "] found");

        if(variables.count(address)) {
            variables[address]->setDynamicSymbol(symbol);
        }
        else {
            variables[address] =
                GlobalVariable::createDynsym(section, address, symbol);
        }
    }
}
