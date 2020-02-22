#include <iomanip>
#include <algorithm>
#include <capstone/x86.h>
#include "addinline.h"
#include "analysis/frametype.h"
#include "disasm/disassemble.h"
#include "instr/register.h"
#include "instr/semantic.h"
#include "instr/linked-x86_64.h"
#include "operation/mutator.h"

#include "log/log.h"
#include "log/temp.h"

ChunkAddInline::ChunkAddInline(std::vector<Register> regList,
    std::function<std::vector<Instruction *> (unsigned int)> generator) {

    modification = new ModificationImpl(regList, generator);
}

std::vector<Instruction *> ChunkAddInline::getFullCode(Instruction *point) {
    auto function = dynamic_cast<Function *>(point->getParent()->getParent());
    assert(function != nullptr);

    bool redzone = !FrameType::hasStackFrame(function);
    SaveRestoreRegisters saveRestore(point, redzone);

    auto regList = modification->getClobberedRegisters();
    unsigned int stackBytesAdded = 0;
    stackBytesAdded += regList.size() * 8;  // for pushes
    if(redzone) stackBytesAdded += 0x80;

    std::vector<Instruction *> instrList;
    extendList(instrList, saveRestore.getRegSaveCode(regList));
    extendList(instrList, modification->getNewCode(stackBytesAdded));
    extendList(instrList, saveRestore.getRegRestoreCode(regList));

    return std::move(instrList);
}

void ChunkAddInline::insertBefore(Instruction *point, bool beforeJumpTo) {
    auto newCode = getFullCode(point);
    auto block = dynamic_cast<Block *>(point->getParent());
    ChunkMutator(block, true).insertBefore(point, newCode, beforeJumpTo);
}

void ChunkAddInline::insertAfter(Instruction *point) {
    auto newCode = getFullCode(point);
    auto block = dynamic_cast<Block *>(point->getParent());
    ChunkMutator(block, true).insertAfter(point, newCode);
}

void ChunkAddInline::extendList(std::vector<Instruction *> &list,
    const std::vector<Instruction *> &additions) {
    
    list.insert(list.end(), additions.begin(), additions.end());
}

ChunkAddInline::InstrList ChunkAddInline::SaveRestoreRegisters::getRegSaveCode(
    const RegList &regList) {

    InstrList results;
    if(redzone && regList.size() > 0) {
        // lea -0x80(%rsp), %rsp
        results.push_back(Disassemble::instruction({0x48, 0x8d, 0x64, 0x24, 0x80}));
    }
    for(auto reg : regList) {
        std::vector<unsigned char> bytes;
        switch(reg) {
        case X86_REG_EFLAGS: bytes = {0x9c}; break;               // pushfd
        case X86_REG_RAX:   bytes = {0x50}; break;                // push %rax
        case X86_REG_RBX:   bytes = {0x53}; break;                // push %rbx
        case X86_REG_RCX:   bytes = {0x51}; break;                // push %rcx
        case X86_REG_RDX:   bytes = {0x52}; break;                // push %rdx
        case X86_REG_RSI:   bytes = {0x56}; break;                // push %rsi
        case X86_REG_RDI:   bytes = {0x57}; break;                // push %rdi
        case X86_REG_RBP:   bytes = {0x55}; break;                // push %rbp
        case X86_REG_RSP:   bytes = {0x54}; break;                // push %rsp
        case X86_REG_R8:    bytes = {0x41, 0x50}; break;          // push %r8
        case X86_REG_R9:    bytes = {0x41, 0x51}; break;          // push %r9
        case X86_REG_R10:   bytes = {0x41, 0x52}; break;          // push %r10
        case X86_REG_R11:   bytes = {0x41, 0x53}; break;          // push %r11
        case X86_REG_R12:   bytes = {0x41, 0x54}; break;          // push %r12
        case X86_REG_R13:   bytes = {0x41, 0x55}; break;          // push %r13
        case X86_REG_R14:   bytes = {0x41, 0x56}; break;          // push %r14
        case X86_REG_R15:   bytes = {0x41, 0x57}; break;          // push %r15
        default:
            LOG(1, "saving unsupported register in ChunkAddInline");
            break;
        }
        results.push_back(Disassemble::instruction(bytes));
    }
    return results;
}

ChunkAddInline::InstrList ChunkAddInline::SaveRestoreRegisters::getRegRestoreCode(
    const RegList &regList) {

    InstrList results;
    for(auto it = regList.rbegin(); it != regList.rend(); it++) {
        auto reg = *it;
        std::vector<unsigned char> bytes;
        switch(reg) {
        case X86_REG_EFLAGS: bytes = {0x9d}; break;               // popfd
        case X86_REG_RAX:   bytes = {0x58}; break;                // pop %rax
        case X86_REG_RBX:   bytes = {0x5b}; break;                // pop %rbx
        case X86_REG_RCX:   bytes = {0x59}; break;                // pop %rcx
        case X86_REG_RDX:   bytes = {0x5a}; break;                // pop %rdx
        case X86_REG_RSI:   bytes = {0x5e}; break;                // pop %rsi
        case X86_REG_RDI:   bytes = {0x5f}; break;                // pop %rdi
        case X86_REG_RBP:   bytes = {0x5d}; break;                // pop %rbp
        case X86_REG_RSP:   bytes = {0x5c}; break;                // pop %rsp
        case X86_REG_R8:    bytes = {0x41, 0x58}; break;          // pop %r8
        case X86_REG_R9:    bytes = {0x41, 0x59}; break;          // pop %r9
        case X86_REG_R10:   bytes = {0x41, 0x5a}; break;          // pop %r10
        case X86_REG_R11:   bytes = {0x41, 0x5b}; break;          // pop %r11
        case X86_REG_R12:   bytes = {0x41, 0x5c}; break;          // pop %r12
        case X86_REG_R13:   bytes = {0x41, 0x5d}; break;          // pop %r13
        case X86_REG_R14:   bytes = {0x41, 0x5e}; break;          // pop %r14
        case X86_REG_R15:   bytes = {0x41, 0x5f}; break;          // pop %r15
        default:
            LOG(1, "restoring unsupported register in ChunkAddInline");
            break;
        }
        results.push_back(Disassemble::instruction(bytes));
    }
    if(redzone && regList.size() > 0) {
        // lea 0x80(%rsp), %rsp
        results.push_back(Disassemble::instruction(
            {0x48, 0x8d, 0xa4, 0x24, 0x80, 0x00, 0x00, 0x00}));
    }
    return results;
}
