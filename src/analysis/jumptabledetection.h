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
        bool valid;
        address_t targetBase;
        address_t tableBase;

        JumptableInfo() : valid(false) {}
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

    address_t parseBaseAddress(UDState *state, int reg);
    address_t parseSavedAddress(UDState *state, int reg);
    address_t parseComputedAddress(UDState *state, int reg);
    address_t parseTableAccess(UDState *state, int reg);

private:
    void check(Instruction *instruction, bool) const;
};

#endif
