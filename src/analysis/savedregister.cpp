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
        detectSaveRegister(s, list);
    }

    return list;
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
            LOG(11, "detected register save: " << std::dec << mem.first);
            LOG(11, "state: " << std::hex
                << state.getInstruction()->getAddress());
            IF_LOG(11) state.dumpState();
            list.push_back(mem.first);
        }
    }
}
#endif
