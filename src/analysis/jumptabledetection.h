#ifndef EGALITO_ANALYSIS_JUMPTABLEDETECTION_H
#define EGALITO_ANALYSIS_JUMPTABLEDETECTION_H

#include "analysis/usedef.h"
#include "analysis/usedefutil.h"
#include "analysis/controlflow.h"
#include "analysis/jumptable.h"

class Function;
class Instruction;
class UDRegMemWorkingSet;

// Assumption: there is only one table that corresponds to one table jump
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

        JumptableInfo(ControlFlowGraph *cfg, UDRegMemWorkingSet *working,
            UDState *state)
            : cfg(cfg), working(working), jumpState(state), valid(false) {}
    };

    std::vector<JumpTableDescriptor *> tableList;

public:
    void detect(Function *function);
    void detect(UDRegMemWorkingSet *working);

private:
    bool containsIndirectJump(Function *function) const;
    bool parseJumptable(UDState *state, TreeCapture cap, JumptableInfo *info);
    void makeDescriptor(UDRegMemWorkingSet *working, Instruction *instruction,
        const JumptableInfo& info);

    bool parseTableAccess(UDState *state, int reg, JumptableInfo *info);
    address_t parseBaseAddress(UDState *state, int reg);
    address_t parseSavedAddress(UDState *state, int reg);
    address_t parseComputedAddress(UDState *state, int reg);

    bool parseBound(UDState *state, int reg, JumptableInfo *info);
    bool getBoundFromCompare(UDState *state, int bound, JumptableInfo *info);
    bool getBoundFromCompareAndBranch(UDState *state, int reg,
        JumptableInfo *info);
    bool getBoundFromMove(UDState *state, int reg, JumptableInfo *info);
    bool getBoundFromIndexTable(UDState *state, int reg, JumptableInfo *info);
    bool getBoundFromArgument(UDState *state, int reg, JumptableInfo *info);

private:
    void check(Instruction *instruction, bool) const;
};

#endif
