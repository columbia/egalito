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

#ifdef ARCH_AARCH64

std::vector<int> SavedRegister::getList(Function *function) {
    ControlFlowGraph cfg(function);
    UDConfiguration config(&cfg);
    UDRegMemWorkingSet working(function, &cfg);
    UseDef usedef(&config, &working);

    SccOrder order(&cfg);
    order.genFull(0);
    usedef.analyze(order.get());

    return getList(&working);
}

std::vector<int> SavedRegister::getList(UDRegMemWorkingSet *working) {
    std::vector<int> list;
    for(auto& s : working->getStateList()) {
        detectMakeFrame(s);
        detectSaveRegister(s, list);
    }

    return list;
}

void SavedRegister::detectMakeFrame(const UDState& state) {
    typedef TreePatternBinary<TreeNodeAddition,
        TreePatternPhysicalRegisterIs<AARCH64GPRegister::SP>,
        TreePatternCapture<TreePatternTerminal<TreeNodeConstant>>
    > MakeFrameForm;

    IF_LOG(10) {
        auto semantic = state.getInstruction()->getSemantic();
        if(auto v = dynamic_cast<DisassembledInstruction *>(semantic)) {
            if(v->getAssembly()->getId() == ARM64_INS_STP) {
                state.dumpState();
            }
        }
    }

    for(auto def : state.getRegDefList()) {
        TreeCapture cap;
        if(MakeFrameForm::matches(def.second, cap)) {
            auto sz = dynamic_cast<TreeNodeConstant *>(cap.get(0))->getValue();
            LOG(10, "detected frame creation [" << std::dec << sz << "]");
        }
    }
}

void SavedRegister::detectSaveRegister(const UDState& state,
    std::vector<int>& list) {

    typedef TreePatternRecursiveBinary<TreeNodeAddition,
        TreePatternCapture<
            TreePatternPhysicalRegisterIs<AARCH64GPRegister::SP>>,
        TreePatternTerminal<TreeNodeConstant>
    > PushForm;

    for(auto mem : state.getMemDefList()) {
        TreeCapture cap;
        if(PushForm::matches(mem.second, cap)) {
            //use MemLocation to simply get offset?

            LOG(10, "detected register save: " << std::dec << mem.first);
            auto regTree = dynamic_cast<TreeNodePhysicalRegister *>(cap.get(0));
            list.push_back(regTree->getRegister());
        }
    }
}
#endif
