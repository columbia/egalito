#ifndef EGALITO_ANALYSIS_JUMPTABLEDETECTION_H
#define EGALITO_ANALYSIS_JUMPTABLEDETECTION_H

#include "analysis/walker.h"
#include "analysis/usedef.h"
#include "analysis/jumptable.h"

class ControlFlowGraph;
class Function;

class JumptableDetection {
private:
    Function *function;
    ControlFlowGraph cfg;

    bool checkFlag;


    typedef TreePatternTerminal<TreeNodeAddress> BaseAddressForm;

    typedef TreePatternBinary<TreeNodeAddition,
        TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>,
        TreePatternTerminal<TreeNodeConstant>
    > MakeBaseAddressForm;

    typedef TreePatternUnary<TreeNodeDereference,
        TreePatternBinary<TreeNodeAddition,
            TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>,
            TreePatternCapture<TreePatternTerminal<TreeNodeConstant>>
        >
    > LoadBaseAddressForm;

    typedef TreePatternUnary<TreeNodeDereference,
        TreePatternBinary<TreeNodeAddition,
            TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>,
            TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>
        >
    > TableOffsetForm1;

    typedef TreePatternUnary<TreeNodeDereference,
        TreePatternBinary<TreeNodeAddition,
            TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>,
            TreePatternBinary<TreeNodeLogicalShiftLeft,
                TreePatternCapture<
                    TreePatternTerminal<TreeNodePhysicalRegister>>,
                TreePatternCapture<TreePatternTerminal<TreeNodeConstant>>
            >
        >
    > TableOffsetForm2;

    typedef TreePatternBinary<TreeNodeAddition,
        TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>,
        TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>
    > MakeJumpTargetForm1;

    typedef TreePatternBinary<TreeNodeAddition,
        TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>,
            TreePatternBinary<TreeNodeLogicalShiftLeft,
                TreePatternCapture<
                    TreePatternTerminal<TreeNodePhysicalRegister>>,
                TreePatternCapture<TreePatternTerminal<TreeNodeConstant>>
            >
    > MakeJumpTargetForm2;

public:
    JumptableDetection(Function *function)
        : function(function), cfg(function) {}

    void detect();

private:
    void detectAt(UDState *state);

    bool parseTableBase(UDState *state, int reg);
    bool parseMakeBase(UDState *state, int reg);
    bool parseTableOffset(UDState *state, int reg);
    bool parseLoadBase(UDState *state, int reg);

    bool containsIndirectJump() const;

    void check(Instruction *instruction, bool) const;
};

#endif
