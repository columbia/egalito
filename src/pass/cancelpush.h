#ifndef EGALITO_PASS_ELIDEPUSH_H
#define EGALITO_PASS_ELIDEPUSH_H

#include <set>
#include <bitset>
#include "chunkpass.h"
#include "analysis/dataflow.h"
#include "analysis/call.h"
#include "analysis/liveregister.h"

class Program;
class Module;
class Function;

class RegisterSet {
private:
    std::bitset<32> s;
public:
    void setAll() { s.set(); }
    void resetAll() { s.reset(); }
    void set(int i) { s[i] = 1; }
    void reset(int i) { s[i] = 0; }
    bool isSet(int i) const { return s[i]; }
    void intersect(const RegisterSet& other) {
        this->s &= other.s;
    }
    bool none() const { return this->s.none(); }

    template <typename FunctionType>
    void forAll(FunctionType fn)
        { for(int i = 0; i < 32; i++) fn(i); }
    template <typename FunctionType>
    void foreachSet(FunctionType fn)
        { for(int i = 0; i < 32; i++) if(s[i]) fn(i); }
    template <typename FunctionType>
    void foreachNot(FunctionType fn)
        { for(int i = 0; i < 32; i++) if(!s[i]) fn(i); }

    void dump() const;
};

class UnusedRegister {
private:
    std::map<Function *, RegisterSet> regsetMap;
public:
    RegisterSet& get(Function *function);
private:
    RegisterSet& detect(Function *function);
};

class CancelPushPass : public ChunkPass {
private:
    Program *program;
    CallGraph graph;
    IndirectCalleeList indirectCallees;
    RegisterSet indirectUnused;
    UnusedRegister unused;
public:
    CancelPushPass(Program *program);
    virtual void visit(Module *Module);
private:
    void optimize(const std::vector<Function *>& rootList);
    void determineUseFrom(Function *root);
    bool hasIndirectCall(Function *function);
};

#endif
