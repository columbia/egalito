#include <cstring>
#include "objectoriented.h"
#include "chunk/concrete.h"
#include "operation/find2.h"
#include "log/log.h"

VTableList *DisassembleVTables::makeVTableList(ElfMap *elfMap,
    SymbolList *symbolList, RelocList *relocList, Module *module,
    Program *program) {

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
            auto vtable = makeVTable(elfMap,
                symbolList, relocList, module, program,
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

VTable *DisassembleVTables::makeVTable(ElfMap *elfMap,
    SymbolList *symbolList, RelocList *relocList, Module *module, Program *program,
    Symbol *vtableSymbol, Symbol *typeinfoSymbol, Symbol *stringSymbol) {

    auto stringSection = elfMap->findSection(".rodata");
    auto tableSection = elfMap->findSection(vtableSymbol->getSectionIndex());
    if(!stringSection || !tableSection) return nullptr;

    if(!typeinfoSymbol || !stringSymbol) {
        // This usually happens because we find a _ZTV symbol from a stripped
        // library where we don't have full symbol information.
        return nullptr;
    }

    auto vtable = new VTable();

    // assume 64-bit architecture here
    size_t index = 0;
    index += 8;  // skip top_offset pointer
    index += 8;  // skip typeinfo pointer
    for( ; index < vtableSymbol->getSize(); index += 8) {
        address_t vtableEntry = vtableSymbol->getAddress() + index;
        LOG(19, "vtableSymbol at " << vtableEntry);
        LOG(19, "vtableSymbol offset "
            << tableSection->convertVAToOffset(vtableEntry));
        auto tablePointer = reinterpret_cast<uint64_t *>(
            tableSection->getReadAddress()
            + tableSection->convertVAToOffset(vtableEntry));
        LOG(19, "dereference " << tableSection->getReadAddress());
        auto value = *tablePointer;

        LOG(15, "got address " << value);

        Link *link = nullptr;
        if(module) {
            auto reloc = relocList->find(vtableEntry);
            if(reloc) {
                if(auto relocSym = reloc->getSymbol()) {
                    LOG(10, "    vtable entry targets ["
                        << relocSym->getName() << "] via reloc");
                    auto target = ChunkFind2(program)
                        .findFunction(relocSym->getName(), module);
                    //auto target = CIter::named(module->getFunctionList())
                        //->find(relocSym->getName());
                    if(target) {
                        LOG(10, "        found");
                        link = new AbsoluteNormalLink(target);
                    }
                }
            }
#if 0
            auto target = CIter::spatial(module->getFunctionList())
                ->findContaining(value);
            if(target && target->getAddress() == value) {
                LOG(9, "    vtable entry targets [" << target->getName() << "]");
                link = new AbsoluteNormalLink(target);
            }
#endif
        }
        else if(value) {
            // the relocation must have been resolved already by the system
            // loader, i.e. we are examining running loader code
            auto symbol = symbolList->find(value);
            if(symbol) {
                LOG(10, "    vtable entry targets ["
                    << symbol->getName() << "] via symbol");
                link = new SymbolOnlyLink(symbol, value);
            }
        }
        if(link) {
            auto entry = new VTableEntry(link);
            entry->setPosition(new AbsolutePosition(vtableEntry));
            vtable->getChildren()->add(entry);
        }
    }

    //auto vtableLink = module->getDataRegionList()->createDataLink(
    //vtable->setVTableLink(dataRegionList->createDataLink

    auto stringPointer = reinterpret_cast<const char *>(
        stringSection->getReadAddress()
        + stringSection->convertVAToOffset(stringSymbol->getAddress()));
    vtable->setClassName(stringPointer);
    LOG(10, "Found a vtable [" << vtableSymbol->getName()
        << "] for class [" << stringPointer << "]");
    return vtable;
}
