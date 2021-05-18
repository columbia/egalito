#include <vector>
#include "syspartpass.h"
#include "disasm/disassemble.h"
#include "instr/register.h"
#include "instr/concrete.h"
#include "operation/mutator.h"


#include "log/log.h"

void SyspartPass::visit(Module *module) {
#ifdef ARCH_X86_64
    if(this->enforcement_func != NULL)
    {
        recurse(module);
        return;
    }
	if(module->getName() != "module-(executable)")
    {
		recurse(module);
        return;
    }
    auto instr = Disassemble::instruction({0xc3});  // ret
    auto block = new Block();

    auto symbol = new Symbol(0x0, 0, "testfn",
       Symbol::TYPE_FUNC, Symbol::BIND_GLOBAL, 0, 0);
    auto function = new Function(symbol);
    function->setName(symbol->getName());
    function->setPosition(new AbsolutePosition(0x0));

    module->getFunctionList()->getChildren()->add(function);
    function->setParent(module->getFunctionList());
    ChunkMutator(function).append(block);
    ChunkMutator(block).append(instr);

    this->enforcement_func = function;
    recurse(module);

#endif
}

void SyspartPass::visit(Function *func)
{
    if((func->getName() == this->function->getName()) && (func->getAddress() == this->function->getAddress()))
    {
        if(special)
        {
            auto call = new Instruction();
                    auto callSem = new ControlFlowInstruction(
            X86_INS_CALL, call, "\xe8", "call", 4);
            callSem->setLink(new NormalLink(enforcement_func, Link::SCOPE_EXTERNAL_JUMP));
            call->setSemantic(callSem);
             for(auto bl : non_loop_parents)
             {
                ChunkMutator m1(bl);
                auto last =  (Instruction*)bl->getChildren()->genericGetLast();
                if(auto cfi = dynamic_cast<ControlFlowInstruction *>(last->getSemantic())) 
                {
                    auto sem1 = last->getSemantic();
                }
                m1.insertBefore(last, call);

             }
        }
        else
        {
            ChunkMutator m1(func);

            auto block2 = new Block();
            ChunkMutator m2(block2);
            auto call = new Instruction();
                    auto callSem = new ControlFlowInstruction(
            X86_INS_CALL, call, "\xe8", "call", 4);
            callSem->setLink(new NormalLink(enforcement_func, Link::SCOPE_EXTERNAL_JUMP));
            call->setSemantic(callSem);
            m2.append(call);
            m1.insertAfter(previous_sibling, block2);
            
            for(auto bl : non_loop_parents)
            {

                auto last =  (Instruction*)bl->getChildren()->genericGetLast();
                if(auto cfi = dynamic_cast<ControlFlowInstruction *>(last->getSemantic())) 
                {
                    auto sem1 = last->getSemantic();
                    if((cfi->getMnemonic())[0] == 'j')
                    {
                        auto link = last->getSemantic()->getLink();
                        last->getSemantic()->setLink(new NormalLink(call, link->getScope()));
                    }
                }
            }
        }
    }
}

