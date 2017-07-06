#include "liveregister.h"
#include "analysis/usedef.h"
#include "analysis/walker.h"
#include "analysis/controlflow.h"
#include "analysis/savedregister.h"
#include "chunk/concrete.h"
#include "instr/register.h"
#include "instr/isolated.h"

#include "log/log.h"

#ifdef ARCH_AARCH64
LiveInfo LiveRegister::getInfo(Function *function) {
    auto it = list.find(function);
    if(it == list.end()) {
        detect(function);
    }
    return list[function];
}

LiveInfo LiveRegister::getInfo(UDRegMemWorkingSet *working) {
    Function *function = working->getFunction();
    auto it = list.find(function);
    if(it == list.end()) {
        detect(working);
    }
    return list[function];
}

void LiveRegister::detect(Function *function) {
    ControlFlowGraph cfg(function);
    UDConfiguration config(&cfg);
    UDRegMemWorkingSet working(function, &cfg);
    UseDef usedef(&config, &working);

    SccOrder order(&cfg);
    order.genFull(0);
    usedef.analyze(order.get());
    detect(&working);
}

void LiveRegister::detect(UDRegMemWorkingSet *working) {
    Function *function = working->getFunction();
    LiveInfo &info = list[function];

    for(const auto& s : working->getStateList()) {
        for(const auto& def : s.getRegDefList()) {
            info.kill(def.first);
        }
    }

    SavedRegister saved;
    for(auto r : saved.getList(function)) {
        info.live(r);
#if 1
        if(r < AARCH64GPRegister::R18) {
            LOG(1, "caller clobbered register saved! " << std::dec << r);
        }
#endif
    }

    LOG0(1, "live registers:");
    for(size_t i = 0; i < 32; i++) {
        if(info.get(i)) {
            LOG0(1, " " << i);
        }
    }
    LOG(1, "");
}

void LiveInfo::kill(int reg) {
    if(reg < 32) {
        regs[reg] = 0;
    }
}

void LiveInfo::live(int reg) {
    if(reg < 32) {
        regs[reg] = 1;
    }
}
#endif
