#include <cassert>
#include <cstring>
#include "twocodealloc.h"
#include "switchcontext.h"
#include "chunk/concrete.h"
#include "chunk/gstable.h"
#include "chunk/link.h"
#include "instr/concrete.h"
#include "operation/find2.h"
#include "operation/mutator.h"
#include "operation/addinline.h"
#include "disasm/disassemble.h"
#include "log/log.h"
#include "log/temp.h"

void TwocodeAllocPass::visit(Program *program) {
    createAllocationFunction(program->getMain());

    if(gsAllocFunc) {
        //SwitchContextPass switchContext;
        //this->gsAllocFunc->accept(&switchContext);

        // add call to shadow stack allocation function in __libc_start_main
        auto call = new Instruction();
        auto callSem = new ControlFlowInstruction(
            X86_INS_CALL, call, "\xe8", "call", 4);
        callSem->setLink(new NormalLink(gsAllocFunc, Link::SCOPE_EXTERNAL_JUMP));
        call->setSemantic(callSem);
        
        {
            auto sourceFunc = ChunkFind2(program).findFunction(
                "_start");
            if(!sourceFunc) {
                sourceFunc = dynamic_cast<Function *>(program->getEntryPoint());
            }
            assert(sourceFunc);
            auto block1 = sourceFunc->getChildren()->getIterable()->get(0);

            {
                ChunkMutator m(block1, true);
                m.prepend(call);
            }
        }
    }

    recurse(program);
}

/*
0000000000000000 <egalito_twocode_set_gs>:
   0:	51                   	push   %rcx
   1:	41 53                	push   %r11
   3:	48 c7 c7 01 10 00 00 	mov    $0x1001,%rdi
   a:	48 8d 35 ef be ad 1e 	lea    0x1eadbeef(%rip),%rsi
  11:	48 c7 c0 9e 00 00 00 	mov    $0x9e,%rax
  18:	0f 05                	syscall 
  1a:	41 5b                	pop    %r11
  1c:	59                   	pop    %rcx
  1d:	c3                   	retq   
*/
void TwocodeAllocPass::createAllocationFunction(Module *module) {
    auto func = new Function();
    func->setPosition(new AbsolutePosition(0));
    func->setName("egalito_twocode_set_gs");

    auto block = new Block();
    auto ret = Disassemble::instruction({0xc3});               // retq
    ChunkMutator(block).append(ret);
    ChunkMutator(func).append(block);

    ChunkAddInline ai({X86_REG_RCX, X86_REG_R11, X86_REG_RAX},
        [this] (unsigned int stackBytesAdded) {

        DisasmHandle handle(true);

        auto ins1 = Disassemble::instruction(
            {0x48, 0xc7, 0xc7, 0x01, 0x10, 0x00, 0x00});            // mov $0x1001,%rdi
        auto ins3 = Disassemble::instruction(
            {0x48, 0xc7, 0xc0, 0x9e, 0x00, 0x00, 0x00 });           // mov $0x9e,%rax
        auto ins4 = Disassemble::instruction({0x0f, 0x05});         // syscall

        // 48 8d 35 ef be ad 1e    lea 0x1eadbeef(%rip),%rsi
        auto ins2 = new Instruction();
        auto semantic2 = new LinkedInstruction(ins4);
        auto asm2 = DisassembleInstruction(handle).makeAssemblyPtr(
            std::vector<unsigned char>({0x48, 0x8d, 0x35, 0, 0, 0, 0}));
        semantic2->setAssembly(asm2);
        semantic2->setLink(new NormalLink(gsArray, Link::SCOPE_WITHIN_MODULE));
        semantic2->setIndex(0);
        ins2->setSemantic(semantic2);

        return std::vector<Instruction *>{ ins1, ins2, ins3, ins4 };
    });
    ai.insertBefore(ret, true);
    module->getFunctionList()->getChildren()->getIterable()->add(func);
    func->setParent(module->getFunctionList());
    this->gsAllocFunc = func;
}
