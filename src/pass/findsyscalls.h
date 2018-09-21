#ifndef EGALITO_PASS_FINDSYSCALLS_H
#define EGALITO_PASS_FINDSYSCALLS_H

#include <map>
#include <set>

#include "chunkpass.h"
#include "log/registry.h"
#include "log/temp.h"

class UDState;

class FindSyscalls : public ChunkPass {
private:
    std::map<Instruction *, std::set<unsigned long>> numberMap;
    std::set<UDState *> seen;
public: 
    virtual void visit(Function *function);

    const std::map<Instruction *, std::set<unsigned long>> &getNumberMap() const
        { return numberMap; }
private:
    bool isSyscallFunction(Function *function);
    bool getRegisterValue(UDState *state, int curreg, std::set<unsigned long> &valueSet);
};

#endif
