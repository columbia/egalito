#ifndef EGALITO_ANALYSIS_JUMPTABLEDETECTION_H
#define EGALITO_ANALYSIS_JUMPTABLEDETECTION_H

#include "analysis/usedef.h"
#include "analysis/usedefutil.h"
#include "analysis/controlflow.h"
#include "analysis/jumptable.h"

class Function;

class JumptableDetection {
private:
    Function *function;
    ControlFlowGraph cfg;

    bool checkFlag;

public:
    JumptableDetection(Function *function)
        : function(function), cfg(function) {}

    void detect();

private:
    void detectAt(UDState *state);

    bool parseBaseAddress(UDState *state, int reg);
    bool parseSavedAddress(UDState *state, int reg);
    bool parseComputedAddress(UDState *state, int reg);
    bool parseJumpOffset(UDState *state, int reg);

    bool parseTableIndex(const std::vector<std::vector<FlowMatchResult>>& list);

    bool containsIndirectJump() const;

    void check(Instruction *instruction, bool) const;
};

#endif
