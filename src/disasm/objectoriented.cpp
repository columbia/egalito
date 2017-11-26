#include <cstring>
#include "objectoriented.h"
#include "chunk/concrete.h"
#include "log/log.h"

VTableList *DisassembleVTables::makeVTableList(ElfMap *elfMap,
    SymbolList *symbolList, Module *module) {

    // This detection strategy only works with full symbol info.
    if(!symbolList) return nullptr;
    //if(!module->getDataRegionList()) return nullptr;

#ifdef ARCH_X86_64
    VTableList *vtableList = new VTableList();

    for(auto symbol : *symbolList) {
        if(std::strncmp(symbol->getName(), "_ZTV", 4) == 0) {
            std::string mainName = std::string(symbol->getName() + 4);

            std::string typeinfoName = "_ZTI" + mainName;
            std::string stringName = "_ZTS" + mainName;
            auto vtable = makeVTable(elfMap, module,
                symbol,
                symbolList->find(typeinfoName.c_str()),
                symbolList->find(stringName.c_str()));
            if(vtable) vtableList->getChildren()->add(vtable);
        }
    }

    return vtableList;
#else
    return nullptr;  // not supported
#endif
}

VTable *DisassembleVTables::makeVTable(ElfMap *elfMap, Module *module,
    Symbol *vtableSymbol, Symbol *typeinfoSymbol, Symbol *stringSymbol) {

    auto section = elfMap->findSection(".rodata");
    if(!section) return nullptr;

    if(!typeinfoSymbol || !stringSymbol) {
        // This usually happens because we find a _ZTV symbol from a stripped
        // library, i.e. we don't have full symbol information.
        return nullptr;
    }

    auto vtable = new VTable();

    //auto vtableLink = module->getDataRegionList()->createDataLink(
    //vtable->setVTableLink(dataRegionList->createDataLink

    auto stringPointer = reinterpret_cast<const char *>(
        section->getReadAddress()
        + section->convertVAToOffset(stringSymbol->getAddress()));
    vtable->setClassName(stringPointer);
    LOG(1, "Found a vtable [" << vtableSymbol->getName() << "] for class ["
        << stringPointer << "]");
    return vtable;
}
