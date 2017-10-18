#ifndef EGALITO_ANALYSIS_FRAMETYPE_H
#define EGALITO_ANALYSIS_FRAMETYPE_H

#include <vector>

class Function;
class Instruction;
class ControlFlowInstruction;

class FrameType {
private:
    Instruction *setBPInstr;
    std::vector<Instruction *> resetSPInstrs;
    std::vector<Instruction *> epilogueInstrs;
    std::vector<ControlFlowInstruction *> jumpToEpilogueInstrs;

public:
    FrameType(Function *function);
    Instruction *getSetBPInstr() const { return setBPInstr; }
    std::vector<Instruction *> getResetSPInstrs() const
        { return resetSPInstrs; }
    std::vector<Instruction *> getEpilogueInstrs() const
        { return epilogueInstrs; }
    void fixEpilogue(Instruction *oldInstr, Instruction *newInstr);
    void setSetBPInstr(Instruction *newInstr) { setBPInstr = newInstr; }
    void dump();

private:
    bool createsFrame(Function *function);
};


#endif
