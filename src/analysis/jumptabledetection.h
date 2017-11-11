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

        TreeNode *indexExpr;

        // keep the initial value of 'entries' to 0, not -1.
        // Setting this to 0 means we are confident that there should be at
        // least one jump for which we can determine the bound. In other
        // words, we do not use JumpTableBounds pass.
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
    bool parseJumptableWithIndexTable(UDState *state, TreeCapture& cap,
        JumptableInfo *info);
    void makeDescriptor(UDRegMemWorkingSet *working, Instruction *instruction,
        const JumptableInfo& info);

    bool parseTableAccess(UDState *state, int reg, JumptableInfo *info);
    std::tuple<bool, address_t> parseBaseAddress(UDState *state, int reg);
    std::tuple<bool, address_t> parseSavedAddress(UDState *state, int reg);
    std::tuple<bool, address_t> parseComputedAddress(UDState *state, int reg);

    bool parseBound(UDState *state, int reg, JumptableInfo *info);
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
#if 0
    bool getBoundFromAny(UDState *state, int reg, JumptableInfo *info);
    void searchForComparison(UDState *state, int reg, JumptableInfo *info,
        std::set<UDState *>& seen, std::set<UDState *>& comparisons);
    void searchForBranch(UDState *state, JumptableInfo *info,
        std::set<UDState *>& comparisons);
#endif
};

#endif
