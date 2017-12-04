#include "ifunc.h"
#include "chunk/gstable.h"
#include "conductor/setup.h"
#include "operation/find2.h"
#include "runtime/managegs.h"

extern ConductorSetup *egalito_conductor_setup;
extern GSTable *egalito_gsTable;
extern IFuncList *egalito_ifuncList;

extern "C"
void ifunc_select(address_t address) {
    auto ifunc = egalito_ifuncList->getFor(address);
    auto funcaddr = reinterpret_cast<address_t>(ifunc());
    //this recursively needs IFUNC
    //if(!isFeatureEnabled("USE_GS_TABLE")) {
    if(!egalito_gsTable) {
        *reinterpret_cast<address_t *>(address) = funcaddr;
    }
    else {
        auto conductor = egalito_conductor_setup->getConductor();
        auto targetFunc
            = ChunkFind2(conductor).findFunctionContaining(funcaddr);
        auto gsEntry = egalito_gsTable->makeEntryFor(targetFunc);
        ManageGS::setEntry(egalito_gsTable, gsEntry->getIndex(), funcaddr);
        *reinterpret_cast<address_t *>(address) = gsEntry->getOffset();
    }
}

void IFuncList::addIFuncFor(address_t address, Chunk *target) {
    auto ifuncEntry = new IFunc(target);
    getChildren()->add(ifuncEntry);
    map[address] = ifuncEntry;
}

auto IFuncList::getFor(address_t address) const -> IFuncType {
    auto it = map.find(address);
    if(it == map.end()) return nullptr;

    return reinterpret_cast<IFuncType>(it->second->getAddress());
}

