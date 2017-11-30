#ifndef EGALITO_PASS_JITGSSETUP_H
#define EGALITO_PASS_JITGSSETUP_H
#include "chunkpass.h"

class Conductor;
class GSTable;

class JitGSSetup : public ChunkPass {
private:
    Conductor *conductor;
    GSTable *gsTable;
public:
    JitGSSetup(Conductor *conductor, GSTable *gsTable)
        : conductor(conductor), gsTable(gsTable) {}
    virtual void visit(Program *program);
private:
    void makeResolverGSEntries(Module *module);
    void makeSupportGSEntries(Program *program);
    void makeResolvedEntry(const char *name, Module *module);
    void makeResolvedEntryForPLT(std::string name, Program *program);
};

#endif
