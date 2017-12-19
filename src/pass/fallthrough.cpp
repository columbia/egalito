#include <cassert>
#include "fallthrough.h"
#include "disasm/disassemble.h"
#include "instr/linked-aarch64.h"
#include "instr/linked-x86_64.h"
#include "instr/register.h"
#include "operation/mutator.h"

#include "log/log.h"

void FallThroughFunctionPass::visit(Function *function) {
    auto block = function->getChildren()->getIterable()->getLast();
    auto instr = block->getChildren()->getIterable()->getLast();

    // doesn't handle functions ending with nop to align the next function yet
    if(auto s = dynamic_cast<ControlFlowInstruction *>(instr->getSemantic())) {
        bool falling = false;
#ifdef ARCH_X86_64
        if(s->getMnemonic() != "callq" && s->getMnemonic() != "jmp") {
            falling = true;
        }
#else
        if(auto assembly = s->getAssembly()) {
            for(size_t r = 0; r < assembly->getImplicitRegsReadCount(); ++r) {
                if(assembly->getImplicitRegsRead()[r] == CONDITION_REGISTER) {
                    falling = true;
                    break;
                }
            }
        }
#endif

        if(falling) {
            auto targetAddress = instr->getAddress() + instr->getSize();
            LOG(10, "Function " << function->getName()
                << " ending with " << s->getMnemonic()
                << " must be connected explicitly to 0x"
                << std::hex << targetAddress);
            auto list = dynamic_cast<FunctionList *>(function->getParent());
            auto target = CIter::spatial(list)->find(targetAddress);
            if(!target) {   // only CISC
                targetAddress = (targetAddress + 15) & ~0xf;
                target = CIter::spatial(list)->find(targetAddress);
            }
            assert(target);
            if(target) {
                auto connecting = new Block();
                LOG(10, "target = " << target->getName());
                // add a branch instruction to the 'target' instruction
                DisasmHandle handle(true);
                auto branch = new Instruction();
#ifdef ARCH_X86_64
                auto semantic = new ControlFlowInstruction(
                    X86_INS_JMP, branch, "\xeb", "jmp", 4);
#elif defined(ARCH_AARCH64)
                auto bin = AARCH64InstructionBinary(
                    0x14000000 | targetAddress >> 2);
                auto semantic = new ControlFlowInstruction(branch);
                semantic->setAssembly(DisassembleInstruction(handle)
                    .makeAssemblyPtr(bin.getVector()));
#endif
                semantic->setLink(new ExternalNormalLink(target));
                branch->setSemantic(semantic);

                ChunkMutator(connecting).append(branch);

                ChunkMutator(function).insertAfter(block, connecting);
            }
        }
    }
}
