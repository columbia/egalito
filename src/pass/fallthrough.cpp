#include <cassert>
#include "config.h"
#include "fallthrough.h"
#include "disasm/disassemble.h"
#include "instr/linked-aarch64.h"
#include "instr/linked-x86_64.h"
#include "instr/register.h"
#include "operation/mutator.h"

#include "log/log.h"
#include "log/temp.h"
#include "chunk/dump.h"

void FallThroughFunctionPass::visit(Function *function) {
    // skip any function that has no blocks
    if(function->getChildren()->getIterable()->getCount() == 0) return;

    //TemporaryLogLevel tll("pass", 10);
    auto block = function->getChildren()->getIterable()->getLast();

    bool falling = true;
    size_t nop = 0;
    for(auto i : CIter::children(block)) {
        auto semantic = i->getSemantic();
        // order is import
        if(dynamic_cast<ReturnInstruction *>(semantic)) {
            falling = false;
        }
        else if(dynamic_cast<IndirectCallInstruction *>(semantic)) {
            falling = false;
        }
        else if(dynamic_cast<IndirectJumpInstruction *>(semantic)) {
            falling = false;
        }
#ifdef ARCH_X86_64
        else if(dynamic_cast<DataLinkedControlFlowInstruction *>(semantic)) {
            falling = false;
        }
#endif
        else if(auto cfi = dynamic_cast<ControlFlowInstruction *>(semantic)) {
            falling = false;
#ifdef ARCH_X86_64
            if(cfi->getMnemonic() != "callq" && cfi->getMnemonic() != "jmp") {
                falling = true;
            }
#elif defined(ARCH_AARCH64)
            auto assembly = semantic->getAssembly();
            assert(assembly);
            bool f = false;
            for(size_t r = 0; r < assembly->getImplicitRegsReadCount(); ++r) {
                if(assembly->getImplicitRegsRead()[r] == CONDITION_REGISTER) {
                    f = true;
                    break;
                }
            }
            falling = f;
#elif defined(ARCH_RISCV)
            auto assembly = semantic->getAssembly();

            if(assembly->getId() == rv_op_j) {
                falling = false;
            }
            else if(assembly->getId() == rv_op_jr) {
                falling = false;
            }
            else if(assembly->getId() == rv_op_c_j) {
                falling = false;
            }
            else if(assembly->getId() == rv_op_c_jr) {
                falling = false;
            }
            else if(assembly->getId() == rv_op_jal) {
                // jal is fall-through unless destination is x0
                auto ops = assembly->getAsmOperands()->getOperands();
                assert(ops[0].type == rv_oper::rv_oper_reg);
                if(ops[0].value.reg == rv_ireg_zero) falling = false;
                else falling = true;
            }
            else if(assembly->getId() == rv_op_jalr) {
                // jalr is fall-through unless destination is x0
                auto ops = assembly->getAsmOperands()->getOperands();
                assert(ops[0].type == rv_oper::rv_oper_reg);
                if(ops[0].value.reg == rv_ireg_zero) falling = false;
                else falling = true;
            }
            // c.jalr always writes to x1, so it's a fall-through
            // c.jal (RV32C-only) likewise
#endif
        }
        else if(dynamic_cast<IsolatedInstruction *>(semantic)) {
            if(auto assembly = semantic->getAssembly()) {
#ifdef ARCH_X86_64
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
#elif defined(ARCH_AARCH64)
                if(assembly->getId() == ARM64_INS_BRK) {
                    falling = false;
                }
                else if(assembly->getId() == ARM64_INS_NOP) {
                    nop++;
                }
#elif defined(ARCH_RISCV)
                if(assembly->getId() == rv_op_illegal) {
                    falling = false;
                }
                // glibc uses ebreak as an "invalid instruction"/abort
                else if(assembly->getId() == rv_op_ebreak) {
                    falling = false;
                }
#endif
                else {
                    falling = true;
                }
            }
            else {
                falling = true;
            }
        }
        else if(dynamic_cast<LiteralInstruction *>(semantic)) {
            falling = false;
        }
        //for archive
        else if(dynamic_cast<LinkedInstruction *>(semantic)) {
            falling = true;
        }
        else if(dynamic_cast<BreakInstruction *>(semantic)) {
            falling = false;
        }
        else {
            assert("FallThroughFunctionPass semantic type?" && 0);
            falling = false;
        }
    }
    if(falling) {
        if(nop == block->getChildren()->getIterable()->getCount()) {
            LOG(9, "WARNING: FallThrough: the last block was all NOPs");
            return ;
        }

        auto instr = block->getChildren()->getIterable()->getLast();
        auto targetAddress = instr->getAddress() + instr->getSize();
        auto list = dynamic_cast<FunctionList *>(function->getParent());
        auto target = CIter::spatial(list)->find(targetAddress);
#if defined(ARCH_AARCH64)
        if(!target) {
            // a gap is usually filled with zero, which is an invalid
            // instruction
            return ;
        }
#endif
        LOG(10, "fallThrough Function " << function->getName());
        if(!target) {   // only CISC
            targetAddress = (targetAddress + 15) & ~0xf;
            target = CIter::spatial(list)->find(targetAddress);
        }
#ifndef LINUX_KERNEL_MODE
        // temporarily disabled
        //assert(target);
#endif
        if(target) {
            auto connecting = new Block();
            PositionFactory *positionFactory
                = PositionFactory::getInstance();

            connecting->setPosition(
                positionFactory->makePosition(block, connecting,
                    function->getSize()));
            LOG(10, "target = " << target->getName());
            // add a branch instruction to the 'target' instruction
            DisasmHandle handle(true);
            auto branch = new Instruction();
#ifdef ARCH_X86_64
            auto semantic = new ControlFlowInstruction(
                X86_INS_JMP, branch, "\xe9", "jmp", 4);
#elif defined(ARCH_AARCH64)
            auto bin = AARCH64InstructionBinary(0x14000000);
            auto semantic = new ControlFlowInstruction(branch);
            semantic->setAssembly(DisassembleInstruction(handle)
                .makeAssemblyPtr(bin.getVector()));
#elif defined(ARCH_RISCV)
            LOG(1, "In function " << function->getName());
            // jmp to next instruction
            std::vector<uint8_t> data{0x6f, 0x00, 0x40, 0x00};

            auto semantic = new ControlFlowInstruction(branch);
            semantic->setAssembly(DisassembleInstruction(handle)
                .makeAssemblyPtr(data));
            LOG(1, "XXX: this fallthrough may not be right");
#endif
            semantic->setLink(
                new NormalLink(target, Link::SCOPE_EXTERNAL_JUMP));
            branch->setSemantic(semantic);

            ChunkMutator(connecting).append(branch);
            ChunkMutator(function).insertAfter(block, connecting);
        }
    }
}
