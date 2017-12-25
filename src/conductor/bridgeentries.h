// no include guards to allow reuse in different context

#ifndef EGALITO_BRIDGE_ENTRY
    #error "Please define EGALITO_BRIDGE_ENTRY(type,name) before including bridgeentries.h"
#endif

#ifdef EGALITO_BRIDGE_FORWARD_DECLARE
#include "types.h"
class ConductorSetup;
class Conductor;
class GSTable;
class Chunk;
class IFuncList;
#endif

EGALITO_BRIDGE_ENTRY(address_t, egalito_entry)
EGALITO_BRIDGE_ENTRY(const char *, egalito_initial_stack)
EGALITO_BRIDGE_ENTRY(address_t, egalito_init_array)

EGALITO_BRIDGE_ENTRY(ConductorSetup *, egalito_conductor_setup)
EGALITO_BRIDGE_ENTRY(Conductor *, egalito_conductor)
EGALITO_BRIDGE_ENTRY(GSTable *, egalito_gsTable)
EGALITO_BRIDGE_ENTRY(Chunk *, egalito_gsCallback)
EGALITO_BRIDGE_ENTRY(IFuncList *, egalito_ifuncList)
