#ifndef EGALITO_CONDUCTOR_PASSES_H
#define EGALITO_CONDUCTOR_PASSES_H

#include "exefile/exefile.h"
#include "chunk/program.h"

class Conductor;
class Module;

class ConductorPasses {
private:
    Conductor *conductor;
public:
    ConductorPasses(Conductor *conductor) : conductor(conductor) {}
    Module *newExePasses(ExeFile *exeFile);
    void newArchivePasses(Program *program);
    void newExecutablePasses(Program *program);
    void newMirrorPasses(Program *program);
    void reloadedArchivePasses(Module *module);
};

#endif
