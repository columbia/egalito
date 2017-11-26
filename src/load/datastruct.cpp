#include <cstring>
#include <sys/mman.h>
#include "datastruct.h"
#include "elf/elfmap.h"
#include "elf/symbol.h"
#include "elf/reloc.h"
#include "disasm/objectoriented.h"
#include "conductor/setup.h"
#include "conductor/conductor.h"
#include "chunk/vtable.h"
#include "chunk/dump.h"
#include "log/log.h"

void DataStructMigrator::migrate(ConductorSetup &setup) {
    auto egalito = setup.getConductor()->getProgram()->getEgalito();
    if(!egalito) return;  // libegalito not injected

    auto egalitoVTableList = egalito->getVTableList();
    if(!egalitoVTableList) {
        LOG(1, "WARNING: no vtable list for libegalito,"
            " cannot migrate data structures");
        return;
    }

    ElfMap *loaderElf = new ElfMap("/proc/self/exe");
    SymbolList *loaderSymbolList = SymbolList::buildSymbolList(loaderElf);
    RelocList *loaderRelocList = RelocList::buildRelocList(
        loaderElf, loaderSymbolList);

    // construct the VTableList with a null Module & Program
    auto loaderVTableList = DisassembleVTables().makeVTableList(
        loaderElf, loaderSymbolList, loaderRelocList, nullptr, nullptr);

    // This relies on VTables having the same name in libegalito
    // as in the loader (i.e. no address in the name).
    for(auto egalitoVTable : CIter::children(egalitoVTableList)) {
        auto named = loaderVTableList->getChildren()->getNamed();
        auto loaderVTable = named->find(egalitoVTable->getName());
        if(loaderVTable) {
            migrateTable(loaderVTable, egalitoVTable);
        }
    }

    delete loaderVTableList;
    delete loaderRelocList;
    delete loaderSymbolList;
    delete loaderElf;

    commit();
}

void DataStructMigrator::migrateTable(VTable *loaderVTable,
    VTable *egalitoVTable) {

    LOG(1, "migrating " << loaderVTable->getName());

    if(egalitoVTable->getChildren()->genericGetSize()
        != loaderVTable->getChildren()->genericGetSize()) {

        LOG(1, "WARNING: vtable entry count mismatch for "
            << loaderVTable->getName() << " -- recompile?");
    }
    else {
        for(size_t i = 0; i < loaderVTable->getChildren()->genericGetSize();
            i ++) {

            auto loaderEntry = loaderVTable->getChildren()->getIterable()->get(i);
            auto egalitoEntry = egalitoVTable->getChildren()->getIterable()->get(i);

            if(!loaderEntry->getLink() || !egalitoEntry->getLink()) continue;

            auto set = loaderEntry->getAddress();
            auto value = egalitoEntry->getLink()->getTargetAddress();
            fixupList.push_back(std::make_pair(set, value));
        }
    }
}

void DataStructMigrator::commit() {
    LOG(1, "Committing all updates to redirect loader vtables to libegalito");
    // NOTE: no virtual functions can be called after this point!

    address_t minAddress = 0, maxAddress = 0;
    for(auto fixup : fixupList) {
        auto address = fixup.first;
        if(!minAddress || address < minAddress) minAddress = address;
        if(!maxAddress || address > maxAddress) maxAddress = address;
    }

    // make memory writable, rounding to nearest page sizes
    minAddress = minAddress & ~0xfff;
    maxAddress = (maxAddress + 0xfff) & ~0xfff;
    void *begin = reinterpret_cast<void *>(minAddress);
    mprotect(begin, maxAddress - minAddress, PROT_READ | PROT_WRITE);

    for(auto fixup : fixupList) {
        auto address = fixup.first;
        auto value = fixup.second;
        std::memcpy(reinterpret_cast<void *>(address), &value, sizeof(value));
    }

    // let's assume all vtables are in the same read-only section
    mprotect(begin, maxAddress - minAddress, PROT_READ);
}
