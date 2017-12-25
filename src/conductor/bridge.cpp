#include "bridge.h"
#include "log/log.h"

LoaderBridge::LoaderBridge() {
    #define EGALITO_BRIDGE_ENTRY(type, name) \
        valueMap[#name] = 0;
    #include "bridgeentries.h"
    #undef EGALITO_BRIDGE_ENTRY
}

LoaderBridge LoaderBridge::instance;

bool LoaderBridge::containsName(const std::string &name) {
    return valueMap.find(name) != valueMap.end();
}

void LoaderBridge::assignAddress(const std::string &name, address_t value) {
    if(valueMap.find(name) == valueMap.end()) {
        LOG(1, "ERROR: assigning value " << value << " to non-existent name \""
            << name << "\" in LoaderBridge");
        return;
    }
    valueMap[name] = value;
}

address_t LoaderBridge::getAddress(const std::string &name) {
    auto it = valueMap.find(name);

    if(it == valueMap.end()) {
        LOG(1, "ERROR: can't find \"" << name << "\" in LoaderBridge");
        throw "unknown LoaderBridge entry";
    }

    return (*it).second;
}
