#ifndef EGALITO_PASS_PROMOTE_JUMPS_H
#define EGALITO_PASS_PROMOTE_JUMPS_H

#include "chunkpass.h"

/** This whole pass is x86_64-specific. */
class PromoteJumpsPass : public ChunkPass {
private:
    bool changed;
public:
    virtual void visit(Module *module) { recurse(module->getFunctionList()); }
    virtual void visit(Function *function);
    virtual void visit(Instruction *instruction);

    template <typename NarrowType>
    static bool fitsIn(address_t address);
private:
    void promote(Instruction *instruction);
    static std::string getWiderOpcode(unsigned int id);
};

template <typename NarrowType>
bool PromoteJumpsPass::fitsIn(address_t address) {
    NarrowType narrow = address;
    return static_cast<signed long>(narrow)
        == static_cast<signed long>(address);
}

#endif
