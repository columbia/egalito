#include "makebridge.h"
#include "conductor/bridge.h"

#define EGALITO_BRIDGE_FORWARD_DECLARE
#define EGALITO_BRIDGE_ENTRY(type, name) \
    extern type name;
#include "conductor/bridgeentries.h"
#undef EGALITO_BRIDGE_ENTRY
#undef EGALITO_BRIDGE_FORWARD_DECLARE

void MakeLoaderBridge::make() {
    LoaderBridge *bridge = LoaderBridge::getInstance();

    #define EGALITO_BRIDGE_ENTRY(type, name) \
        bridge->assignAddress(#name, reinterpret_cast<address_t>(&name));
    #include "conductor/bridgeentries.h"
    #undef EGALITO_BRIDGE_ENTRY
}
