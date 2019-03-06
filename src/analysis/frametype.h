#ifndef EGALITO_ANALYSIS_FRAMETYPE_H
#define EGALITO_ANALYSIS_FRAMETYPE_H

#include <vector>

class Function;
class Instruction;
class ControlFlowInstruction;

class FrameType {
private:
    bool hasFrame;
    Instruction *setBPInstr;
    Instruction *setSPInstr;
    std::vector<Instruction *> resetSPInstrs;
    std::vector<Instruction *> epilogueInstrs;
    std::vector<ControlFlowInstruction *> jumpToEpilogueInstrs;

public:
    FrameType(Function *function);
    bool createsFrame() { return hasFrame; }
    Instruction *getSetBPInstr() const { return setBPInstr; }
    Instruction *getSetSPInstr() const { return setSPInstr; }
    std::vector<Instruction *> getResetSPInstrs() const
        { return resetSPInstrs; }
    std::vector<Instruction *> getEpilogueInstrs() const
        { return epilogueInstrs; }
    void fixEpilogue(Instruction *oldInstr, Instruction *newInstr);
    void setSetBPInstr(Instruction *newInstr) { setBPInstr = newInstr; }
    void dump();

    static bool hasStackFrame(Function *function);
};


#endif
