#ifndef EGALITO_ANALYSIS_LIVEDREGISTER_H
#define EGALITO_ANALYSIS_LIVEDREGISTER_H

#include <bitset>
#include <map>
#include "analysis/usedef.h"

#ifdef ARCH_AARCH64
class Function;
class UDState;

class LiveInfo {
private:
    std::bitset<32> regs;

public:
    LiveInfo() : regs(0xFFFFFFFF) {}
    void kill(int reg);
    void live(int reg);
    bool get(int reg) { return regs[reg]; }
    const std::bitset<32>& get() const { return regs; }
};

class LiveRegister {
private:
    std::map<Function *, LiveInfo> list;

public:
    LiveInfo getInfo(Function *function);
    LiveInfo getInfo(UDRegMemWorkingSet *working);

    void detect(Function *function);
    void detect(UDRegMemWorkingSet *working);
};
#endif

#endif
