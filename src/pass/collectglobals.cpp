#include "elf/symbol.h"
#include "exefile/exefile.h"
#include "chunk/dataregion.h"

#include "collectglobals.h"

#include "log/log.h"

void CollectGlobalsPass::visit(Module *module) {
    auto exeFile = module->getExeFile();
    if(!exeFile) return;
    if(exeFile->asPE()) return;  // for now, not supported on PE
    if(!module->getDataRegionList()) return;

    auto syms = exeFile->getSymbolList();
    auto dynsyms = exeFile->getDynamicSymbolList();

    std::map<address_t, GlobalVariable *> variables;

    if(syms) {
        for(auto symbol : *syms) {
            if(symbol->getType() != Symbol::TYPE_OBJECT) continue;
            if(symbol->getAliasFor()) continue;

            address_t address = symbol->getAddress();
            DataSection *section =
                module->getDataRegionList()->findDataSectionContaining(address);

            if(!section) continue;

            LOG(10, "symtab global variable [" << (symbol->getName()) << "] found");

            variables[address] =
                GlobalVariable::createSymtab(section, address, symbol);
        }
    }

    if(dynsyms) {
        for(auto symbol : *dynsyms) {
            if(symbol->getType() != Symbol::TYPE_OBJECT) continue;
            if(symbol->getAliasFor()) continue;

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
}
