#ifndef EGALITO_SHELL_LOOP_H
#define EGALITO_SHELL_LOOP_H

#include "command.h"

class TopLevelCommand : public CompositeCommand {
public:
    TopLevelCommand() : CompositeCommand("", "") {}
    virtual void invokeNull(Arguments args) {}
    virtual void invokeDefault(Arguments args);
};

void mainLoop();

#endif
