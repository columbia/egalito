#include "ifunc.h"

extern IFuncList *egalito_ifuncList;

extern "C"
void ifunc_select(address_t address) {
    auto ifunc = egalito_ifuncList->getFor(address);
    auto funcaddr = reinterpret_cast<address_t>(ifunc());
    *reinterpret_cast<address_t *>(address) = funcaddr;
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

