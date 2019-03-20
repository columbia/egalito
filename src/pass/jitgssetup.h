#ifndef EGALITO_PASS_JITGSSETUP_H
#define EGALITO_PASS_JITGSSETUP_H

#include "chunkpass.h"

class ConductorSetup;
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
    void makeHardwiredGSEntries(Module *egalito);
    void makeResolverGSEntries(Module *egalito);
    void makeSupportGSEntries(Program *program);
    void makeResolvedEntry(const char *name, Module *module);
    void makeResolvedEntryForClass(const char *name, Module *module);
    void makeResolvedEntryForFunction(Function *function);
    //void makeResolvedEntryForPLT(std::string name, Program *program);
    void makeResolvedEntryForPLT(PLTTrampoline *plt);

    void makeRequiredEntries();
    void makeRequiredEntriesFor(Chunk *chunk);
};

#endif
