#include <cassert>
#include "fallthrough.h"
#include "disasm/disassemble.h"
#include "instr/linked-aarch64.h"
#include "instr/linked-x86_64.h"
#include "instr/register.h"
#include "operation/mutator.h"

#include "log/log.h"
#include "log/temp.h"

void FallThroughFunctionPass::visit(Function *function) {
    auto block = function->getChildren()->getIterable()->getLast();

    bool falling = true;
    size_t nop = 0;
    for(auto i : CIter::children(block)) {
        auto semantic = i->getSemantic();
        // order is import
        if(dynamic_cast<ReturnInstruction *>(semantic)) {
            falling = false;
        }
        else if(dynamic_cast<IndirectJumpInstruction *>(semantic)) {
            falling = false;
        }
        else if(auto cfi = dynamic_cast<ControlFlowInstruction *>(semantic)) {
            falling = false;
#ifdef ARCH_X86_64
            if(cfi->getMnemonic() != "callq" && cfi->getMnemonic() != "jmp") {
                falling = true;
            }
#elif defined(ARCH_AARCH64)
            auto assembly = s->getAssembly();
            assert(assembly);
            for(size_t r = 0; r < assembly->getImplicitRegsReadCount(); ++r) {
                if(assembly->getImplicitRegsRead()[r] == CONDITION_REGISTER) {
                    falling = true;
                    break;
                }
            }
#endif
        }
        else if(dynamic_cast<IsolatedInstruction *>(semantic)) {
            if(auto assembly = semantic->getAssembly()) {
                if(assembly->getId() == X86_INS_UD2) {
                    falling = false;
                }
                else if(assembly->getId() == X86_INS_HLT) {
                    falling = false;
                }
                else if(assembly->getId() == X86_INS_CALL) {
                    // this is not LinkedInstruction yet if
                    // RIP-relative
                    falling = false;
                }
                else if(assembly->getId() == X86_INS_JMP) {
                    // this is not LinkedInstruction yet if
                    // RIP-relative
                    falling = false;
                }
                else if(assembly->getId() == X86_INS_SYSCALL) {
                    falling = false;
                }
                else if(assembly->getId() == X86_INS_NOP) {
                    nop++;
                }
                else {
                    falling = true;
                }
            }
            else {
                falling = true;
            }
        }
        else {
            assert("FallThroughFunctionPass" && 0);
            falling = false;
        }
    }
    if(falling) {
        if(nop != block->getChildren()->getIterable()->getCount()) {
            LOG(10, "fallThrough Function " << function->getName());
        }
        auto instr = block->getChildren()->getIterable()->getLast();
        auto targetAddress = instr->getAddress() + instr->getSize();
        auto list = dynamic_cast<FunctionList *>(function->getParent());
        auto target = CIter::spatial(list)->find(targetAddress);
        if(!target) {   // only CISC
            targetAddress = (targetAddress + 15) & ~0xf;
            target = CIter::spatial(list)->find(targetAddress);
        }
        assert(target);
        if(target) {
            auto connecting = new Block();
            PositionFactory *positionFactory
                = PositionFactory::getInstance();

            connecting->setPosition(
                positionFactory->makePosition(block, connecting,
                    function->getSize()));
            LOG(1, "target = " << target->getName());
            // add a branch instruction to the 'target' instruction
            DisasmHandle handle(true);
            auto branch = new Instruction();
#ifdef ARCH_X86_64
            auto semantic = new ControlFlowInstruction(
                X86_INS_JMP, branch, "\xe9", "jmp", 4);
#elif defined(ARCH_AARCH64)
            auto bin = AARCH64InstructionBinary(
                0x14000000 | targetAddress >> 2);
            auto semantic = new ControlFlowInstruction(branch);
            semantic->setAssembly(DisassembleInstruction(handle)
                .makeAssemblyPtr(bin.getVector()));
#endif
            semantic->setLink(
                new NormalLink(target, Link::SCOPE_EXTERNAL_JUMP));
            branch->setSemantic(semantic);

            ChunkMutator(connecting).append(branch);
            ChunkMutator(function).insertAfter(block, connecting);
        }
    }
}
