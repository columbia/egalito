#ifndef EGALITO_SHELL_DISASS_H
#define EGALITO_SHELL_DISASS_H

#include "command.h"

class ConductorSetup;

class DisassCommands {
private:
    ConductorSetup *setup;
public:
    DisassCommands(ConductorSetup *setup) : setup(setup) {}

    void registerCommands(CompositeCommand *topLevel);
};

#endif
