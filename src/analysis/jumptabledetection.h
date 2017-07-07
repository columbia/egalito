#ifndef EGALITO_ANALYSIS_JUMPTABLEDETECTION_H
#define EGALITO_ANALYSIS_JUMPTABLEDETECTION_H

#include "analysis/usedef.h"
#include "analysis/usedefutil.h"
#include "analysis/controlflow.h"
#include "analysis/jumptable.h"

class Function;
class UDRegMemWorkingSet;

class JumptableDetection {
public:
    JumptableDetection() {}

    void detect(Function *function);
    void detect(UDRegMemWorkingSet *working);

private:
    void detectAt(UDState *state);

    bool parseBaseAddress(UDState *state, int reg);
    bool parseSavedAddress(UDState *state, int reg);
    bool parseComputedAddress(UDState *state, int reg);
    bool parseJumpOffset(UDState *state, int reg);

    bool parseTableIndex(const std::vector<std::vector<FlowMatchResult>>& list);

    bool containsIndirectJump(Function *function) const;

private:
    void check(Instruction *instruction, bool) const;
};

#endif
