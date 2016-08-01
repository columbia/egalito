#ifndef EGALITO_BREAK_BREAKPOINT_H
#define EGALITO_BREAK_BREAKPOINT_H

#include <vector>
#include "types.h"

class Breakpoint {
private:
    address_t address;
    char originalData;
public:
    Breakpoint(address_t address);
};

class BreakpointManager {
private:
    std::vector<Breakpoint *> list;
public:
    Breakpoint *set(address_t address);
};

#endif
