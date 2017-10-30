#include <cstddef>
#include "reguse.h"
#include "chunk/concrete.h"
#include "instr/instr.h"
#include "instr/semantic.h"
#ifdef ARCH_X86_64
#include "instr/linked-x86_64.h"
#endif
#ifdef ARCH_AARCH64
#include "instr/linked-aarch64.h"
#endif
#include "log/log.h"

AARCH64RegisterUsageX::AARCH64RegisterUsageX(Function *function,
    AARCH64GPRegister::ID id) : function(function), regX(id, true) {

    for(auto block : function->getChildren()->getIterable()->iterable()) {
        for(auto ins : block->getChildren()->getIterable()->iterable()) {
            if(auto assembly = ins->getSemantic()->getAssembly()) {
                auto asmOps = assembly->getAsmOperands();
                for(size_t i = 0; i < asmOps->getOpCount(); ++i) {
                    auto& op = asmOps->getOperands()[i];
                    if(op.type == ARM64_OP_REG) {
                        if(AARCH64GPRegister(op.mem.base, false).id() == id) {
                            xList.push_back(ins);
                            break;
                        }
                    }
                    if(op.type == ARM64_OP_MEM) {
                        if(AARCH64GPRegister(op.mem.base, false).id() == id) {
                            xList.push_back(ins);
                            break;
                        }
                        if(AARCH64GPRegister(op.mem.index, false).id() == id) {
                            xList.push_back(ins);
                            break;
                        }
                    }
                }
            }
        }
    }
}

std::vector<bool> AARCH64RegisterUsageX::getUnusableRegister() {
    bool unusable[AARCH64GPRegister::REGISTER_NUMBER];
    for(size_t i = 0; i < AARCH64GPRegister::REGISTER_NUMBER; ++i) {
        unusable[i] = false;
    }
    for(auto ins : xList) {
        if(auto assembly = ins->getSemantic()->getAssembly()) {
            auto asmOps = assembly->getAsmOperands();
            bool withX = false;
            std::vector<int> regOperands;
            for(size_t i = 0; i < asmOps->getOpCount(); ++i) {
                if(asmOps->getOperands()[i].type == ARM64_OP_REG) {
                    int id = PhysicalRegister<AARCH64GPRegister>(
                        asmOps->getOperands()[i].reg, false).id();

                    if(id == AARCH64GPRegister::INVALID) continue;
                    if(id == regX.id()) {
                        withX = true;
                    }
                    regOperands.push_back(id);
                }

                if(withX) {
                    for(auto rid : regOperands) {
                        unusable[rid] = true;
                    }
                }
            }
        }
    }

    return std::vector<bool>(unusable,
                             unusable + AARCH64GPRegister::REGISTER_NUMBER);
}

std::vector<int> AARCH64RegisterUsage::getAllUseCounts(Function *function) {
    int use_count[AARCH64GPRegister::REGISTER_NUMBER];
    for(size_t i = 0; i < AARCH64GPRegister::REGISTER_NUMBER; ++i) {
        use_count[i] = 0;
    }

    for(auto block : function->getChildren()->getIterable()->iterable()) {
        for(auto ins : block->getChildren()->getIterable()->iterable()) {
            if(auto assembly = ins->getSemantic()->getAssembly()) {
                auto asmOps = assembly->getAsmOperands();
                for(size_t i = 0; i < asmOps->getOpCount(); ++i) {
                    if(asmOps->getOperands()[i].type == ARM64_OP_REG) {
                        int id = PhysicalRegister<AARCH64GPRegister>(
                            asmOps->getOperands()[i].reg, false).id();

                        if(id == AARCH64GPRegister::INVALID) continue;
                        ++use_count[id];
                    }
                }
            }
        }
    }
    return std::vector<int>(use_count,
                            use_count + AARCH64GPRegister::REGISTER_NUMBER);
}

