#ifndef EGALITO_SHELL_DISASS_H
#define EGALITO_SHELL_DISASS_H

#include "command.h"

class ConductorSetup;

void registerDisassCommands(CompositeCommand *topLevel, ConductorSetup *&setup);

#endif
