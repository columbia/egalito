#include "ifunc.h"

IFuncList::IFuncType *egalito_ifunc_table;

void IFuncList::add(address_t address, Chunk *target) {
    auto ifuncEntry = new IFunc(target);
    getChildren()->add(ifuncEntry);
    map[address] = ifuncEntry;
}

void *IFuncList::getFor(address_t address) const {
    auto it = map.find(address);
    if(it == map.end()) return nullptr;

    return reinterpret_cast<void *>(it->second->getAddress());
}
