#ifndef EGALITO_LOAD_LOADER_H
#define EGALITO_LOAD_LOADER_H

#include "conductor/setup.h"

class EgalitoLoader {
private:
    ConductorSetup setup;
public:
    bool parse(const char *filename);

    void generateCode();
    void run(int argc, char *argv[]);
private:
    void otherPasses();
};

#endif
