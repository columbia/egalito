#include <vector>
#include <cassert>
#include "aflcoverage.h"
#include "disasm/disassemble.h"
#include "instr/register.h"
#include "instr/concrete.h"
#include "operation/mutator.h"
#include "operation/addinline.h"
#include "operation/find2.h"
#include "pass/switchcontext.h"
#include "types.h"

void AFLCoveragePass::visit(Program *program) {
    auto allocateFunc = ChunkFind2(program).findFunction(
        "egalito_allocate_afl_shm");

    if(allocateFunc) {
        SwitchContextPass switchContext;
        allocateFunc->accept(&switchContext);

        // add call to afl shm allocate function in __libc_start_main
        auto call = new Instruction();
        auto callSem = new ControlFlowInstruction(
            X86_INS_CALL, call, "\xe8", "call", 4);
        callSem->setLink(new NormalLink(allocateFunc, Link::SCOPE_EXTERNAL_JUMP));
        call->setSemantic(callSem);
        
        {
            auto sourceFunc = ChunkFind2(program).findFunction(
                "__libc_start_main");
            assert(sourceFunc && "AFLCoveragePass requires libc to be present (uniongen)");
            auto block1 = sourceFunc->getChildren()->getIterable()->get(0);

            {
                ChunkMutator m(block1, true);
                m.prepend(call);
            }
        }
    }

    if(auto f = dynamic_cast<Function *>(program->getEntryPoint())) {
        entryPoint = f;
    }

    recurse(program);
}

void AFLCoveragePass::visit(Module *module) {
    if(module->getLibrary()->getRole() != Library::ROLE_EXTRA) {
        recurse(module);
    }
}

void AFLCoveragePass::visit(Function *function) {
    if(function->getName() == "obstack_free") return;  // jne tail rec, for const ss

    if(function->getName() == "_start" || function == entryPoint) return;
    if(function->getName() == "__libc_start_main") return;
    if(function->getName() == "mmap64") return;
    if(function->getName() == "mmap") return;
    if(function->getName() == "arch_prctl") return;

    // const shadow stack needs these
    if(function->getName() == "__longjmp") return;
    if(function->getName() == "__longjmp_chk") return;

    // mempcpy does jmp into middle of this:
    //if(function->getName() == "__memcpy_avx_unaligned_erms") return;
    if(function->getName().find("memcpy") != std::string::npos) return;

    // memcpy does jmp into middle of this:
    //if(function->getName() == "__memmove_sse2_unaligned_erms") return;
    if(function->getName().find("memmove") != std::string::npos) return;

    // this has ja, conditional tail recursion
    //if(function->getName() == "__memset_avx2_unaligned_erms") return;
    if(function->getName().find("memset") != std::string::npos) return;

    // blacklist all mem* functions?
    //if(function->getName().find("mem") != std::string::npos) return;

    // this has jne, conditional tail recursion
    // __strncasecmp_l_avx
    //if(function->getName() == "__strncasecmp_l_avx") return;
    if(function->getName().find("str") != std::string::npos) return;

    // sphinx3, function does tail recursion to itself
    if(function->getName() == "mdef_phone_id") return;

    recurse(function);
}

void AFLCoveragePass::visit(Block *block) {
    addCoverageCode(block);
}

#define GET_BYTE(x, shift) static_cast<unsigned char>(((x) >> (shift*8)) & 0xff)
#define GET_BYTES(x) GET_BYTE((x),0), GET_BYTE((x),1), GET_BYTE((x),2), GET_BYTE((x),3)

#define SHM_REGION 0x50000000
#define SHM_QUEUE_PTR (SHM_REGION - 0x1000)

void AFLCoveragePass::addCoverageCode(Block *block) {
    ChunkAddInline ai({X86_REG_R10}, [this] (unsigned int stackBytesAdded) {
        //   0:   41 52                   push   %r10
        //   2:   4c 8b 15 cc cc 0c 00    mov    0xccccc(%rip),%r10        # 0xcccd5
        //   9:   49 83 c2 08             add    $0x8,%r10
        //   d:   49 c7 02 01 00 00 00    movq   $0x1,(%r10)
        //  14:   4c 89 15 dd dd 00 00    mov    %r10,0xdddd(%rip)        # 0xddf8
        //  1b:   41 5a                   pop    %r10

        // 0:   41 53                   push   %r11
        // 2:   4c 8b 5c 24 08          mov    0x8(%rsp),%r11
        // 7:   4c 89 9c 24 00 00 50    mov    %r11,-0xb00000(%rsp)
        // e:   ff
        // f:   41 5b                   pop    %r11

        DisasmHandle handle(true);

        //   2:   4c 8b 15 cc cc 0c 00    mov    0xccccc(%rip),%r10        # 0xcccd5
        auto mov1Instr = new Instruction();
        auto mov1Sem = new LinkedInstruction(mov1Instr);
        mov1Sem->setAssembly(DisassembleInstruction(handle).makeAssemblyPtr(
            std::vector<unsigned char>{0x4c, 0x8b, 0x15, 0x00, 0x00, 0x00, 0x00}));
        mov1Sem->setLink(new UnresolvedRelativeLink(SHM_QUEUE_PTR));
        mov1Sem->setIndex(0);
        mov1Instr->setSemantic(mov1Sem);

        //   9:   49 83 c2 08             add    $0x8,%r10
        auto addInstr = Disassemble::instruction({0x49, 0x83, 0xc2, 0x08});

        //   d:   49 c7 02 01 00 00 00    movq   $0x1,(%r10)
        auto mov2Instr = Disassemble::instruction({0x49, 0xc7, 0x02, GET_BYTES(blockID)});

        //  14:   4c 89 15 dd dd 00 00    mov    %r10,0xdddd(%rip)        # 0xddf8
        auto mov3Instr = new Instruction();
        auto mov3Sem = new LinkedInstruction(mov3Instr);
        mov3Sem->setAssembly(DisassembleInstruction(handle).makeAssemblyPtr(
            std::vector<unsigned char>{0x4c, 0x89, 0x15, 0x00, 0x00, 0x00, 0x00}));
        mov3Sem->setLink(new UnresolvedRelativeLink(SHM_QUEUE_PTR));
        mov3Sem->setIndex(1);
        mov3Instr->setSemantic(mov3Sem);

        return std::vector<Instruction *>{ mov1Instr, addInstr, mov2Instr, mov3Instr };
    });
	auto instr1 = block->getChildren()->getIterable()->get(0);
    ai.insertBefore(instr1, false);

    blockID ++;
}

#undef GET_BYTE
#undef GET_BYTES
