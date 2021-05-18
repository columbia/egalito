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
/*
void SyspartPass::visit(Function *func)
{

    
	if((func->getName() == this->function->getName()) && (func->getAddress() == this->function->getAddress()))
	{
		for(auto bl : CIter::children(this->function))
		{
			for(auto instr : CIter::children(bl))
			{
				if(instr->getAddress() == this->address)
				{
                    auto block2 = new Block();
                    //PositionFactory *positionFactory = PositionFactory::getInstance();
                    //block2->setPosition(positionFactory->makePosition(bl, block2, bl->getSize()));
                    ChunkMutator m1(block2);

					auto call = new Instruction();
					auto callSem = new ControlFlowInstruction(
            X86_INS_CALL, call, "\xe8", "call", 4);
                    auto module = (Module*)func->getParent()->getParent();
                    auto newRef = CIter::named(module->getPLTList())->find(enforcement_func->getName());
                    if(newRef)
                    {
                        LOG(1, "YEAH PLT ENTRY FOUND");
                        callSem->setLink(new PLTLink(newRef->getAddress(), newRef));
                    }
                    else
                    {
                        LOG(1, "NAAH PLT ENTRY NOT FOUND");
            		    callSem->setLink(new NormalLink(enforcement_func, Link::SCOPE_EXTERNAL_JUMP));
                    }
            		call->setSemantic(callSem);
                    m1.append(call);
                    ChunkMutator m2(func);
                    m2.insertAfter(bl, block2); */
                    /*
            		{
            			ChunkMutator m(bl, true);
            			//m.prepend(call);
                        if(before)
            			     m.insertBeforeJumpTo(instr, call);
                         else
            			     m.append(call);

            			return;
            		}*/
                    /*
				}
			}
		}
	}
}
*/

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
                    //cout<<"CFI at "<< std::hex<<last->getAddress()<<endl;
                    auto sem1 = last->getSemantic();
                    /*
		    if(auto linked = dynamic_cast<LinkedInstructionBase *>(sem1))
                    {
                        cout<<"LINKED INSTRUCTION BASE"<<endl;
                    }
                    if(auto linked = dynamic_cast<ControlFlowInstructionBase *>(sem1))
                    {
                        cout<<"CONTROL FLOW INSTRUCTION BASE "<<(linked->getSource())->getAddress()<<endl;
                    }
                    if((cfi->getMnemonic())[0] == 'j')
                    {
                       cout<<"JUMP HERE"<<endl;
                    }
		    */
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
            //cout<<"Appended call"<<endl;
            m1.insertAfter(previous_sibling, block2);
            //m1.insertBefore(previous_sibling, block2);
            //auto last_instr = previous_sibling->getChildren()->genericGetLast();
            //cout<<"Previous sibling "<<previous_sibling->getAddress()<<" "<<last_instr->getAddress()<<endl;

            //ChunkMutator m1(previous_sibling);
            //m1.append(call);
            //m1.insertAfter(last_instr, call);
            cout<<"Added block"<<endl;
            for(auto bl : non_loop_parents)
            {
                //if(bl->getAddress() == previous_sibling->getAddress())
                //    continue;
                auto last =  (Instruction*)bl->getChildren()->genericGetLast();
                if(auto cfi = dynamic_cast<ControlFlowInstruction *>(last->getSemantic())) 
                {
                    cout<<"CFI at "<< std::hex<<last->getAddress()<<endl;
                    auto sem1 = last->getSemantic();
                    if(auto linked = dynamic_cast<LinkedInstructionBase *>(sem1))
                    {
                        cout<<"LINKED INSTRUCTION BASE"<<endl;
                    }
                    if(auto linked = dynamic_cast<ControlFlowInstructionBase *>(sem1))
                    {
                        cout<<"CONTROL FLOW INSTRUCTION BASE "<<(linked->getSource())->getAddress()<<endl;
                    }
                    if((cfi->getMnemonic())[0] == 'j')
                    {
                        auto link = last->getSemantic()->getLink();
                        last->getSemantic()->setLink(new NormalLink(call, link->getScope()));
                        //auto sem1 = last->getSemantic();
                        //if(auto linked = dynamic_cast<LinkedInstructionBase *>(sem1))
                            //linked->setInstruction(call);
                        //if(auto linked = dynamic_cast<ControlFlowInstructionBase *>(sem1))
                            //linked->setSource(call);
                    }
                }
            }
        }
    }
}

