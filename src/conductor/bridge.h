#ifndef EGALITO_CONDUCTOR_BRIDGE_H
#define EGALITO_CONDUCTOR_BRIDGE_H

#include <string>
#include <map>
#include "types.h"

#if 0
enum BridgeEntryType {
    #define EGALITO_BRIDGE_ENTRY(type, name) \
        BRIDGE_ ## name,
    #include "bridgeentries.h"
    #undef EGALITO_BRIDGE_ENTRY
    BRIDGES
};
#endif

class LoaderBridge {
private:
    static LoaderBridge instance;
    LoaderBridge();
public:
    static LoaderBridge *getInstance() { return &instance; }
private:
    std::map<std::string, address_t> valueMap;
public:
    bool containsName(const std::string &name);
    void assignAddress(const std::string &name, address_t value);
    address_t getAddress(const std::string &name);
};

#endif
