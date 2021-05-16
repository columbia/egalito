#ifndef EGALITO_PASS_SYSCALL_SANDBOX_H
#define EGALITO_PASS_SYSCALL_SANDBOX_H

#include<set>
using namespace std;

#include "chunkpass.h"

class SyspartPass : public ChunkPass {
private:
    Program *program;
    Function *function;
    address_t address;
    Function *enforcement_func;
    bool special;
    Block* previous_sibling;
    set<Block*> non_loop_parents;
public:
    SyspartPass(Program *program, Function* function, address_t address, Function *enforcement_func, bool special, Block* previous_sibling, set<Block*> non_loop_parents ) : program(program), function(function), address(address), enforcement_func(enforcement_func), special(special), previous_sibling(previous_sibling), non_loop_parents(non_loop_parents) {}
    virtual void visit(Function *func);
    virtual void visit(Module *module);
};

#endif