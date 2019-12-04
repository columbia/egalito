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
    if(function->getName() == "__GI__IO_file_xsputn") return;
    if(function->getName() == "vfprintf") return;

    if(function->getName() == "_start" || function == entryPoint) return;
    if(function->getName() == "__libc_csu_init") return;

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
#define SHM_REGION_SIZE 0x10000
#define SHM_QUEUE_PTR (SHM_REGION - 0x1000)

void AFLCoveragePass::addCoverageCode(Block *block) {
    blockID = std::rand(); //% SHM_REGION_SIZE;

    ChunkAddInline ai({X86_REG_R10, X86_REG_EFLAGS}, [this] (unsigned int stackBytesAdded) {
#if 1
		//   0:   41 52                   push   %r10
		//   2:   4c 8b 15 cc cc 0c 00    mov    0xccccc(%rip),%r10        # 0xcccd5
		//   9:   49 d1 ea                shr    %r10
		//   c:   49 81 f2 11 11 11 11    xor    $0x11111111,%r10
		//  13:   4c 89 15 cc cc 0c 00    mov    %r10,0xccccc(%rip)        # 0xccce6
		//  1a:   49 81 e2 ff ff 00 00    and    $0xffff,%r10
		//  21:   41 fe 82 00 00 00 50    incb   0x50000000(%r10)
		//  28:   41 5a                   pop    %r10


        DisasmHandle handle(true);

		//   2:   4c 8b 15 cc cc 0c 00    mov    0xccccc(%rip),%r10        # 0xcccd5
        auto mov1Instr = new Instruction();
        auto mov1Sem = new LinkedInstruction(mov1Instr);
        mov1Sem->setAssembly(DisassembleInstruction(handle).makeAssemblyPtr(
            std::vector<unsigned char>{0x4c, 0x8b, 0x15, 0x00, 0x00, 0x00, 0x00}));
        mov1Sem->setLink(new UnresolvedRelativeLink(SHM_QUEUE_PTR));
        mov1Sem->setIndex(0);
        mov1Instr->setSemantic(mov1Sem);

		//  17:   49 d1 ea                shr    %r10
        auto shrInstr = Disassemble::instruction({0x49, 0xd1, 0xea});


		//   c:   49 81 f2 11 11 11 11    xor    $0x11111111,%r10
        auto xorInstr = Disassemble::instruction({0x49, 0x81, 0xf2, GET_BYTES(blockID)});


        //  14:   4c 89 15 cc cc cc 00    mov    %r10,0xccccc(%rip)        # 0xddf8
        auto mov2Instr = new Instruction();
        auto mov2Sem = new LinkedInstruction(mov2Instr);
        mov2Sem->setAssembly(DisassembleInstruction(handle).makeAssemblyPtr(
            std::vector<unsigned char>{0x4c, 0x89, 0x15, 0x00, 0x00, 0x00, 0x00}));
        mov2Sem->setLink(new UnresolvedRelativeLink(SHM_QUEUE_PTR));
        mov2Sem->setIndex(1);
        mov2Instr->setSemantic(mov2Sem);

		//  1a:   49 81 e2 ff ff 00 00    and    $0xffff,%r10
        auto andInstr = Disassemble::instruction({0x49, 0x81, 0xe2, GET_BYTES(SHM_REGION_SIZE - 1)});

		//  10:   41 fe 82 00 00 00 50    incb   0x50000000(%r10)
        auto incInstr = Disassemble::instruction({0x41, 0xfe, 0x82, GET_BYTES(SHM_REGION)});

        return std::vector<Instruction *>{ mov1Instr, shrInstr, xorInstr, mov2Instr, andInstr, incInstr };
#else  // 16-bit history version
		//   0:   41 52                   push   %r10
		//   2:   49 c7 c2 01 00 00 00    mov    $0x0001,%r10
		//   9:   4c 33 15 cc cc 0c 00    xor    0xccccc(%rip),%r10        # 0xcccdc
		//  10:   41 fe 82 00 00 00 50    incb   0x50000000(%r10)
		//  17:   49 d1 ea                shr    %r10
		//  1a:   4c 89 15 cc cc 0c 00    mov    %r10,0xccccc(%rip)        # 0xccced
		//  21:   41 5a                   pop    %r10

		blockID %= SHM_REGION_SIZE;

        DisasmHandle handle(true);

		//   2:   49 c7 c2 01 00 00 00    mov    $0x0001,%r10
        auto mov1Instr = Disassemble::instruction({0x49, 0xc7, 0xc2, GET_BYTES(blockID)});

		//   9:   4c 33 15 cc cc 0c 00    xor    0xccccc(%rip),%r10        # 0xcccdc
        auto xorInstr = new Instruction();
        auto xorSem = new LinkedInstruction(xorInstr);
        xorSem->setAssembly(DisassembleInstruction(handle).makeAssemblyPtr(
            std::vector<unsigned char>{0x4c, 0x33, 0x15, 0x00, 0x00, 0x00, 0x00}));
        xorSem->setLink(new UnresolvedRelativeLink(SHM_QUEUE_PTR));
        xorSem->setIndex(0);
        xorInstr->setSemantic(xorSem);

		//  10:   41 fe 82 00 00 00 50    incb   0x50000000(%r10)
        auto incInstr = Disassemble::instruction({0x41, 0xfe, 0x82, GET_BYTES(SHM_REGION)});

		//  17:   49 d1 ea                shr    %r10
        auto shrInstr = Disassemble::instruction({0x49, 0xd1, 0xea});

        //  14:   4c 89 15 cc cc cc 00    mov    %r10,0xccccc(%rip)        # 0xddf8
        auto mov2Instr = new Instruction();
        auto mov2Sem = new LinkedInstruction(mov2Instr);
        mov2Sem->setAssembly(DisassembleInstruction(handle).makeAssemblyPtr(
            std::vector<unsigned char>{0x4c, 0x89, 0x15, 0x00, 0x00, 0x00, 0x00}));
        mov2Sem->setLink(new UnresolvedRelativeLink(SHM_QUEUE_PTR));
        mov2Sem->setIndex(1);
        mov2Instr->setSemantic(mov2Sem);

        return std::vector<Instruction *>{ mov1Instr, xorInstr, incInstr, shrInstr, mov2Instr };
#endif
    });
	auto instr1 = block->getChildren()->getIterable()->get(0);
    ai.insertBefore(instr1, true);
}

#undef GET_BYTE
#undef GET_BYTES
