#include "savedregister.h"
#include "analysis/usedef.h"
#include "analysis/walker.h"
#include "analysis/controlflow.h"
#include "chunk/concrete.h"
#include "instr/register.h"
#include "instr/isolated.h"

#include "log/log.h"
#include "log/temp.h"

#include "log/registry.h"

std::vector<int> SavedRegister::makeList(Function *function) {
    ControlFlowGraph cfg(function);
    UDConfiguration config(&cfg);
    UDRegMemWorkingSet working(function, &cfg);
    UseDef usedef(&config, &working);

    SccOrder order(&cfg);
    order.genFull(0);
    usedef.analyze(order.get());

    TemporaryLogLevel tll("analysis", 5);

    for(auto& s : working.getStateList()) {
        detectMakeFrame(&s);
        detectSaveRegister(&s);
    }

    return {};
}

bool SavedRegister::detectMakeFrame(const UDState *state) {
    typedef TreePatternBinary<TreeNodeAddition,
        TreePatternPhysicalRegisterIs<AARCH64GPRegister::SP>,
        TreePatternCapture<TreePatternTerminal<TreeNodeConstant>>
    > MakeFrameForm;

    IF_LOG(9) {
        auto semantic = state->getInstruction()->getSemantic();
        if(auto v = dynamic_cast<DisassembledInstruction *>(semantic)) {
            if(v->getAssembly()->getId() == ARM64_INS_STP) {
                state->dumpState();
            }
        }
    }

    for(auto def : state->getRegDefList()) {
        TreeCapture cap;
        if(MakeFrameForm::matches(def.second, cap)) {
            auto sz = dynamic_cast<TreeNodeConstant *>(cap.get(0))->getValue();
            LOG(1, "detected frame creation [" << std::dec << sz << "]");

            //detectSaveRegister(state);

            return true;
        }
    }
    return false;
}

bool SavedRegister::detectSaveRegister(const UDState *state) {
    typedef TreePatternRecursiveBinary<TreeNodeAddition,
        TreePatternPhysicalRegisterIs<AARCH64GPRegister::SP>,
        TreePatternTerminal<TreeNodeConstant>
    > PushForm;

    bool found = false;
    for(auto mem : state->getMemDefList()) {
        TreeCapture cap;
        if(PushForm::matches(mem.second, cap)) {
            //use MemLocation to simply get offset?

            LOG(1, "detected register save: " << std::dec << mem.first);
            found = true;
        }
    }

    return found;
}
