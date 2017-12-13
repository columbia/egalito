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
        if(auto assembly = s->getAssembly()) {
            for(size_t r = 0; r < assembly->getImplicitRegsReadCount(); ++r) {
                if(assembly->getImplicitRegsRead()[r] == CONDITION_REGISTER) {
                    falling = true;
                    break;
                }
            }
        }

        if(falling) {
            auto targetAddress = instr->getAddress() + instr->getSize();
            LOG(1, "Function " << function->getName()
                << " must be connected explicitly to 0x"
                << std::hex << targetAddress);
            auto list = dynamic_cast<FunctionList *>(function->getParent());
            auto target = CIter::spatial(list)->find(targetAddress);
            if(target) {
                LOG(10, "target = " << target->getName());
                // add a branch instruction to the 'target' instruction
#ifdef ARCH_AARCH64
                DisasmHandle handle(true);
                auto bin = AARCH64InstructionBinary(
                    0x14000000 | targetAddress >> 2);
                auto branch = new Instruction();
                auto semantic = new ControlFlowInstruction(branch);
                semantic->setAssembly(DisassembleInstruction(handle)
                    .makeAssemblyPtr(bin.getVector()));
                semantic->setLink(new ExternalNormalLink(target));
                branch->setSemantic(semantic);

                ChunkMutator(block).insertAfter(instr, branch);
#else
                LOG(9, "FallThroughFunctionPass: NYI");
#endif
            }
            else {
                LOG(1, "but not found!");
            }
        }
    }
}
