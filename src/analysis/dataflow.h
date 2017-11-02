#ifndef EGALITO_ANALYSIS_DATAFLOW_H
#define EGALITO_ANALYSIS_DATAFLOW_H

#include "analysis/usedef.h"
#include "analysis/liveregister.h"

class Module;
class Program;

class DataFlow {
private:
    std::map<Function *, UseDef *> flowList;
    std::vector<UDRegMemWorkingSet *> workingList;
    std::vector<UDConfiguration *> configList;
    std::vector<ControlFlowGraph *> graphList;

public:
    ~DataFlow();
    void addUseDefFor(Function *function);
    void adjustCallUse(LiveRegister *live, Function *function, Module *module);
    void adjustPLTCallUse(LiveRegister *live, Function *function,
        Program *program);
    UDRegMemWorkingSet *getWorkingSet(Function *function);

private:
    bool isTLSdescResolveCall(UDState *state, Module *module);
    void adjustUse(LiveRegister *live, Instruction *instruction,
        Function *source, Function *target, bool viaTrampoline);
};

#endif
