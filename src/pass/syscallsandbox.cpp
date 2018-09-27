#include <sstream>
#include "syscallsandbox.h"
#include "findsyscalls.h"
#include "operation/find2.h"
#include "operation/mutator.h"
#include "chunk/block.h"
#include "instr/instr.h"
#include "instr/concrete.h"
#include "disasm/disassemble.h"
#include "log/log.h"

void SyscallSandbox::visit(Function *function) {
    FindSyscalls findSyscalls;
    function->accept(&findSyscalls);
    auto list = findSyscalls.getNumberMap();
    for(auto kv : list) {
        auto syscallInstr = kv.first;
        auto syscallValues = kv.second;
        if(syscallValues.size() != 1) {
            LOG(1, "ERROR: expected one possible system call value, got "
                << syscallValues.size() << " possibilities, at "
                << syscallInstr->getName() << " inside ["
                << syscallInstr->getParent()->getParent()->getName() << "]");
            continue;
        }
        int value = static_cast<int>(*syscallValues.begin());

        std::ostringstream name;
        name << "egalito_sandbox_syscall_" << value;

        auto func = ChunkFind2(program).findFunction(name.str().c_str());
        if (!func) {
            LOG(2, "Looking for sandbox enforcement function [" << name.str()
                << "], not found!");
            continue;
        }

        addEnforcement(function, syscallInstr, func);
    }
}

void SyscallSandbox::addEnforcement(Function *function, Instruction *syscallInstr, Function*enforce) {
    /*
           0:   51                      push   %rcx
           1:   4c 89 d1                mov    %r10,%rcx
           4:   50                      push   %rax

                                        ; call enforce

           6:   49 89 c3                mov    %rax,%r11
           9:   58                      pop    %rax
           a:   59                      pop    %rcx
           b:   4d 85 db                test   %r11,%r11
           e:   74 02                   je     12 <skip>

          10:   0f 05                   syscall 

        0000000000000012 <skip>:
          12:   90                      nop
    */

    auto epilogue = static_cast<Instruction *>(syscallInstr->getNextSibling());
    if(!epilogue) {
        LOG(3, "Expected instruction after system call at " << syscallInstr->getName());
        return;
    }

    auto block1 = static_cast<Block*>(syscallInstr->getParent());
    {
        ChunkMutator m(function, true);
        m.splitBlockBefore(epilogue);
        m.splitBlockBefore(syscallInstr);
    }

    {
        ChunkMutator bm(block1, true);
        bm.append(Disassemble::instruction({0x51}));    // push %rcx
        bm.append(Disassemble::instruction({0x4c, 0x89, 0xd1}));    // mov %r10, %rcx
        bm.append(Disassemble::instruction({0x50}));    // push %rax

        auto callIns = new Instruction();
        auto callSem
            = new ControlFlowInstruction(X86_INS_CALL, callIns, "\xe8", "callq", 4);
        callSem->setLink(new NormalLink(enforce, Link::SCOPE_EXTERNAL_JUMP));
        callIns->setSemantic(callSem);
        bm.append(callIns);
    }

    auto block3 = static_cast<Block*>(epilogue->getParent());

    {
        auto block2 = new Block();
        ChunkMutator(function, true).insertAfter(block1, block2);

        ChunkMutator bm(block2, true);
        bm.append(Disassemble::instruction({0x49, 0x89, 0xc3}));    // mov %rax, %r11
        bm.append(Disassemble::instruction({0x58}));    // pop %rax
        bm.append(Disassemble::instruction({0x59}));    // pop %rcx
        bm.append(Disassemble::instruction({0x4d, 0x85, 0xdb}));    // test %r11, %r11

        // create new near 1-byte jz instruction
        auto jmpIns = new Instruction();
        auto jmpSem
            = new ControlFlowInstruction(X86_INS_JE, jmpIns, "\x74", "je", 1);
        jmpSem->setLink(new NormalLink(block3, Link::SCOPE_INTERNAL_JUMP));
        jmpIns->setSemantic(jmpSem);
        bm.append(jmpIns);
    }

    //ChunkMutator(function, true);  // recalculate everything

    LOG(9, "Adding sandbox enforcement to syscall in [" << function->getName() << "]");
}
