#ifndef EGALITO_ANALYSIS_JUMPTABLEDETECTION_H
#define EGALITO_ANALYSIS_JUMPTABLEDETECTION_H

#include <vector>
#include <set>
#include "analysis/usedef.h"
#include "analysis/usedefutil.h"
#include "analysis/controlflow.h"
#include "analysis/jumptable.h"

class Module;
class Function;
class Instruction;
class UDRegMemWorkingSet;

class JumptableDetection {
private:
    struct JumptableInfo {
        ControlFlowGraph *cfg;
        UDRegMemWorkingSet *working;
        UDState *jumpState;

        bool valid;
        address_t targetBase;
        address_t tableBase;
        size_t scale;
        long entries;

        JumptableInfo(ControlFlowGraph *cfg, UDRegMemWorkingSet *working,
            UDState *state)
            : cfg(cfg), working(working), jumpState(state), valid(false),
              targetBase(0), tableBase(0), scale(0), entries(0) {}
    };

    struct IndextableInfo {
        address_t base;
        size_t scale;
        long entries;

        IndextableInfo(size_t scale, long entries)
            : scale(scale), entries(entries) {}
    };

    Module *module;
    std::vector<JumpTableDescriptor *> tableList;
    std::map<Instruction *, std::vector<JumpTableDescriptor *>> tableMap;

    // keeps track of index table for performance and correct analysis
    // because the non-first use of index table requires complex analysis
    std::map<address_t /* index table base */, IndextableInfo> indexTables;

public:
    JumptableDetection(Module *module) : module(module) {}
    void detect(Module *module);
    void detect(Function *function);
    void detect(UDRegMemWorkingSet *working);
    const std::vector<JumpTableDescriptor *> &getTableList() const
        { return tableList; }

private:
    bool containsIndirectJump(Function *function) const;
    bool parseJumptable(UDState *state, TreeCapture& cap, JumptableInfo *info);
    void parseOldCJumptable(UDState *state, int reg, JumptableInfo *info);
    bool parseJumptableWithIndexTable(UDState *state, int reg,
        JumptableInfo *info);
    void makeDescriptor(Instruction *instruction, const JumptableInfo *info);

    bool parseTableAccess(UDState *state, int reg, JumptableInfo *info);
    std::tuple<bool, address_t> parseBaseAddress(UDState *state, int reg);
    std::tuple<bool, address_t> parseSavedAddress(UDState *state, int reg);
    std::tuple<bool, address_t> parseMovedAddress(UDState *state, int reg);
    std::tuple<bool, address_t> parseComputedAddress(UDState *state, int reg);

    bool parseBound(UDState *state, int reg, JumptableInfo *info);
    bool parseBoundDeref(UDState *state, TreeNodeDereference *deref,
        int reg, JumptableInfo *info);
    bool getBoundFromCompare(UDState *state, int bound, JumptableInfo *info);
    bool getBoundFromCompareAndBranch(UDState *state, int reg,
        JumptableInfo *info);
    bool getBoundFromSub(UDState *state, int reg, JumptableInfo *info);
    bool getBoundFromMove(UDState *state, int reg, JumptableInfo *info);
    bool getBoundFromAnd(UDState *state, int reg, JumptableInfo *info);
    bool getBoundFromLoad(UDState *state, int reg, JumptableInfo *info);
    bool getBoundFromBitTest(UDState *state, int reg, JumptableInfo *info);
    bool getBoundFromIndexTable(UDState *state, int reg, JumptableInfo *info);
    bool getBoundFromArgument(UDState *state, int reg, JumptableInfo *info);
    bool getBoundFromControlFlow(UDState *state, int reg, JumptableInfo *info);

    void collectJumpsTo(UDState *state, JumptableInfo *info,
        std::set<UDState *>& visited, std::vector<UDState *>& result);
    bool valueReaches(UDState *state, int reg, UDState *state2, int reg2,
        long *boundValue);
};

#endif
