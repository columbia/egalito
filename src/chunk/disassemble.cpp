#include <cstdio>
#include <cstring>
#include <capstone/x86.h>
#include <capstone/arm64.h>
#include "disassemble.h"
#include "elf/symbol.h"
#include "chunk/chunk.h"
#include "chunk/instruction.h"
#include "log/log.h"

Disassemble::Handle::Handle(bool detailed) {
#ifdef ARCH_X86_64
    if(cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        throw "Can't initialize capstone handle!";
    }
#elif defined(ARCH_AARCH64)
    if(cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &handle) != CS_ERR_OK) {
        throw "Can't initialize capstone handle!";
    }
#endif

    cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);  // AT&T syntax
    if(detailed) {
        cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    }
}

Disassemble::Handle::~Handle() {
    cs_close(&handle);
}

std::string Disassemble::formatBytes(const char *bytes, size_t size) {
    IF_LOG(10) {
        char buffer[16*3 + 1];
        size_t pos = 0;
        for(size_t i = 0; i < size; i ++) {
            pos += sprintf(buffer + pos, "%02x ", (unsigned)bytes[i] & 0xff);
        }
        return std::string(buffer);
    }

    return std::string();
}

void Disassemble::printInstruction(cs_insn *instr, int offset,
    const char *name) {

    // show disassembly of each instruction
    std::string rawDisasm = formatBytes(
        reinterpret_cast<const char *>(instr->bytes), instr->size);

    printInstructionRaw(instr->address, offset, instr->mnemonic,
        instr->op_str, name, rawDisasm);
}

void Disassemble::printInstructionRaw(unsigned long address, int offset,
    const char *opcode, unsigned long target, const char *name,
    const std::string &rawDisasm) {

    char targetString[64];
    sprintf(targetString, "0x%lx", target);

    printInstructionRaw(address, offset, opcode, targetString, name, rawDisasm);
}

#define APPEND(...) \
    pos += std::snprintf(buffer + pos, sizeof buffer - pos, __VA_ARGS__)
void Disassemble::printInstructionRaw(unsigned long address, int offset,
    const char *opcode, const char *args, const char *name,
    const std::string &rawDisasm) {

    char buffer[1024];
    size_t pos = 0;

    IF_LOG(10) {
        const int displaySize = 10 * 3;
        APPEND("%-*s ", displaySize, rawDisasm.size() ? rawDisasm.c_str() : "---");
    }

    APPEND("0x%08lx", address);

    if(offset != INT_MIN) {
        APPEND(" <+%3d>: ", offset);
    }
    else {
        APPEND(":        ");
    }

    APPEND(" %-12s %-20s", opcode, args);

    if(name) {
        APPEND("<%s>", name);
    }

    std::printf("%s\n", buffer);
}

void Disassemble::debug(const uint8_t *code, size_t length,
    address_t realAddress, SymbolList *symbolList) {

    Handle handle(symbolList != 0);
    cs_insn *insn;
    size_t count = cs_disasm(handle.raw(), code, length, realAddress, 0, &insn);
    if(count == 0) {
        CLOG(3, "# empty");
        return;
    }
    for(size_t j = 0; j < count; j++) {
        const char *name = 0;
#ifdef ARCH_X86_64
        if(symbolList && insn[j].id == X86_INS_CALL) {
            cs_x86_op *op = &insn[j].detail->x86.operands[0];
            if(op->type == X86_OP_IMM) {
                unsigned long imm = op->imm;
                auto sym = symbolList->find(imm);
                if(sym) {
                    name = sym->getName();
                }
            }
        }
#elif defined(ARCH_AARCH64)
        if(symbolList && insn[j].id == ARM64_INS_BL) {
            cs_arm64_op *op = &insn[j].detail->arm64.operands[0];
            if (op->type == ARM64_OP_IMM) {
                unsigned long imm = op->imm;
                auto sym = symbolList->find(imm);
                if(sym) {
                    name = sym->getName();
                }
            }
        }
#endif

        IF_LOG(3) printInstruction(&insn[j], INT_MIN, name);
    }

    cs_free(insn, count);
}

Function *Disassemble::function(Symbol *symbol, address_t baseAddr,
    SymbolList *symbolList) {

    address_t readAddress = baseAddr + symbol->getAddress();
    address_t trueAddress = symbol->getAddress();
    Handle handle(true);
    cs_insn *insn;
    size_t count = cs_disasm(handle.raw(),
        (const uint8_t *)readAddress, symbol->getSize(),
        trueAddress, 0, &insn);

    Function *function = new Function(symbol);
    function->setPosition(new AbsolutePosition(symbol->getAddress()));
    Block *block = new Block();
    block->setPosition(new RelativePosition(block, function->getSize()));

    for(size_t j = 0; j < count; j++) {
        auto ins = &insn[j];
        auto instr = new Instruction();
        InstructionSemantic *semantic = nullptr;

#ifdef ARCH_X86_64
        // check if this instruction ends the current basic block
        bool split = false;
        if(cs_insn_group(handle.raw(), ins, X86_GRP_JUMP)) {
            split = true;
        }
        else if(cs_insn_group(handle.raw(), ins, X86_GRP_CALL)) {
            split = true;
        }
        else if(cs_insn_group(handle.raw(), ins, X86_GRP_RET)) {
            split = true;
        }
        else if(cs_insn_group(handle.raw(), ins, X86_GRP_INT)) {
        }
        else if(cs_insn_group(handle.raw(), ins, X86_GRP_IRET)) {
        }
#elif defined(ARCH_AARCH64)
        bool split = false;
        if (cs_insn_group(handle.raw(), ins, ARM64_GRP_JUMP)) { //only branches
            split = true;
        }
        else if(ins->id == ARM64_INS_BL) {
            split = true;
        }
        else if(ins->id == ARM64_INS_BLR) {
            split = true;
        }
        else if(ins->id == ARM64_INS_RET) {
            split = true;
        }
        //exception generation instructions don't require split
#endif

        cs_detail *detail = ins->detail;
#ifdef ARCH_X86_64
        cs_x86 *x = &detail->x86;
#elif defined(ARCH_AARCH64)
        cs_arm64 *x = &detail->arm64;
#endif
        if(x->op_count > 0) {
            for(size_t p = 0; p < x->op_count; p ++) {
#ifdef ARCH_X86_64
                cs_x86_op *op = &x->operands[p];
                if(op->type == X86_OP_IMM) {
#elif defined(ARCH_AARCH64)
                cs_arm64_op *op = &x->operands[p];
                if(op->type == ARM64_OP_IMM) {
#endif
                    //CLOG0(3, "    immediate operand in ");
                    //IF_LOG(3) printInstruction(ins);

#ifdef ARCH_X86_64
                    if(ins->id == X86_INS_CALL) {
                        unsigned long imm = op->imm;
                        auto cfi = new ControlFlowInstruction(instr,
                            std::string((char *)ins->bytes,
                            ins->size - 4),
                            ins->mnemonic,
                            4);
                        cfi->setLink(new UnresolvedLink(imm));
                        semantic = cfi;
                    }
                    else if(cs_insn_group(handle.raw(), ins, X86_GRP_JUMP)) {

#if 0
                        if(op->size <= ins->size) {
                            unsigned long imm = op->imm;
                            auto cfi = new ControlFlowInstruction(instr,
                                std::string((char *)ins->bytes,
                                ins->size - op->size),
                                ins->mnemonic,
                                op->size);
                            cfi->setLink(new UnresolvedLink(imm));
                            semantic = cfi;
                        }
                        else {
                            std::cout << "total size " << ins->size
                                << ", op size " << (int)op->size << std::endl;
                            printInstruction(ins, "BUG", 0);
                        }
#else
                        // !!! should subtract op->size,
                        // !!! can't right now due to bug in capstone
                        size_t use = ins->size /* - op->size*/;
                        unsigned long imm = op->imm;
                        auto cfi = new ControlFlowInstruction(instr,
                            std::string((char *)ins->bytes, use),
                            ins->mnemonic,
                            /*op->size*/ 0);
                        cfi->setLink(new UnresolvedLink(imm));
                        semantic = cfi;
#endif
                    }
#elif defined(ARCH_AARCH64)
                    if(ins->id == ARM64_INS_BL) {
                        unsigned long imm = op->imm;
                        auto cfi = new ControlFlowInstruction(instr,
                            std::string((char *)ins->bytes,
                            ins->size - 4),
                            ins->mnemonic,
                            4);
                        cfi->setLink(new UnresolvedLink(imm));
                        semantic = cfi;
                    }
                    else if(cs_insn_group(handle.raw(), ins, ARM64_GRP_JUMP)) {
                        size_t use = ins->size /* - op->size*/;
                        unsigned long imm = op->imm;
                        auto cfi = new ControlFlowInstruction(instr,
                            std::string((char *)ins->bytes, use),
                            ins->mnemonic,
                            /*op->size*/ 0);
                        cfi->setLink(new UnresolvedLink(imm));
                        semantic = cfi;
                    }
#endif
                }
            }
        }

        if(!semantic) {
#if 1
            semantic = new DisassembledInstruction(*ins);
#else
            if(split) {
                semantic = new DisassembledInstruction(*ins);
            }
            else {
                std::string raw;
                raw.assign(reinterpret_cast<char *>(ins->bytes), ins->size);
                semantic = new RawInstruction(raw);
            }
#endif
        }
        instr->setSemantic(semantic);
        //instr->setPosition(new RelativePosition(instr, block->getSize()));
        //instr->setPosition(new SubsequentPosition(instr, block->getSize()));
        if(block->getChildren()->getIterable()->getCount() > 0) {
            instr->setPosition(new SubsequentPosition(
                block->getChildren()->getIterable()->getLast()));
        }
        else if(function->getChildren()->getIterable()->getCount() > 0) {
            instr->setPosition(new SubsequentPosition(
                function->getChildren()->getIterable()->getLast()));
        }
        else {
            instr->setPosition(new RelativePosition(instr, 0));
        }

        block->getChildren()->add(instr);
        instr->setParent(block);
        block->addToSize(instr->getSize());
        if(split) {
            function->getChildren()->add(block);
            block->setParent(function);
            function->addToSize(block->getSize());

            Block *oldBlock = block;
            block = new Block();
            //block->setPosition(new RelativePosition(block, function->getSize()));
            block->setPosition(new SubsequentPosition(oldBlock));
        }
    }

    if(block->getSize() == 0) {
        delete block;
    }
    else {
        CLOG0(1, "fall-through function [%s]... "
            "adding basic block\n", symbol->getName());
        function->getChildren()->add(block);
        block->setParent(function);
        function->addToSize(block->getSize());
    }

    cs_free(insn, count);
    return function;
}

cs_insn Disassemble::getInsn(std::string str, address_t address) {
    Handle handle(true);

    cs_insn *insn;
    if(cs_disasm(handle.raw(), (const uint8_t *)str.data(), str.size(),
        address, 0, &insn) != 1) {

        throw "Invalid instruction opcode string provided\n";
    }

    cs_insn ret = *insn;
    cs_free(insn, 1);
    return ret;
}

cs_insn Disassemble::getInsn(const std::vector<unsigned char> &str, address_t address) {
    Handle handle(true);

    cs_insn *insn;
    if(cs_disasm(handle.raw(), (const uint8_t *)str.data(), str.size(),
        address, 0, &insn) != 1) {

        throw "Invalid instruction opcode string provided\n";
    }

    cs_insn ret = *insn;
    cs_free(insn, 1);
    return ret;
}

Instruction *Disassemble::instruction(
    const std::vector<unsigned char> &bytes, bool details, address_t address) {

    auto instr = new Instruction();
    InstructionSemantic *semantic = nullptr;

    Handle handle(true);
    cs_insn *ins;
    if(cs_disasm(handle.raw(), (const uint8_t *)bytes.data(), bytes.size(),
        address, 0, &ins) != 1) {

        throw "Invalid instruction opcode string provided\n";
    }

    cs_detail *detail = ins->detail;
#ifdef ARCH_X86_64
    cs_x86 *x = &detail->x86;
#elif defined(ARCH_AARCH64)
    cs_arm64 *x = &detail->arm64;
#endif
    if(x->op_count > 0) {
        for(size_t p = 0; p < x->op_count; p ++) {
#ifdef ARCH_X86_64
            cs_x86_op *op = &x->operands[p];
            if(op->type == X86_OP_IMM) {
#elif defined(ARCH_AARCH64)
            cs_arm64_op *op = &x->operands[p];
            if(op->type == ARM64_OP_IMM) {
#endif

#ifdef ARCH_X86_64
                if(ins->id == X86_INS_CALL) {
                    unsigned long imm = op->imm;
                    auto cfi = new ControlFlowInstruction(instr,
                        std::string((char *)ins->bytes,
                        ins->size - 4),
                        ins->mnemonic,
                        4);
                    cfi->setLink(new UnresolvedLink(imm));
                    semantic = cfi;
                }
                else if(cs_insn_group(handle.raw(), ins, X86_GRP_JUMP)) {

                    // !!! should subtract op->size,
                    // !!! can't right now due to bug in capstone
                    size_t use = ins->size /* - op->size*/;
                    unsigned long imm = op->imm;
                    auto cfi = new ControlFlowInstruction(instr,
                        std::string((char *)ins->bytes, use),
                        ins->mnemonic,
                        /*op->size*/ 0);
                    cfi->setLink(new UnresolvedLink(imm));
                    semantic = cfi;
                }
#elif defined(ARCH_AARCH64)
                if(ins->id == ARM64_INS_BL) {
                    unsigned long imm = op->imm;
                    auto cfi = new ControlFlowInstruction(instr,
                        std::string((char *)ins->bytes,
                        ins->size - 4),
                        ins->mnemonic,
                        4);
                    cfi->setLink(new UnresolvedLink(imm));
                    semantic = cfi;
                }
                else if(cs_insn_group(handle.raw(), ins, ARM64_GRP_JUMP)) {
                    size_t use = ins->size /* - op->size*/;
                    unsigned long imm = op->imm;
                    auto cfi = new ControlFlowInstruction(instr,
                        std::string((char *)ins->bytes, use),
                        ins->mnemonic,
                        /*op->size*/ 0);
                    cfi->setLink(new UnresolvedLink(imm));
                    semantic = cfi;
                }
#endif
            }
        }
    }

    if(!semantic) {
        if(details) {
            semantic = new DisassembledInstruction(*ins);
        }
        else {
            std::string raw;
            raw.assign(reinterpret_cast<char *>(ins->bytes), ins->size);
            semantic = new RawInstruction(raw);
        }
    }
    instr->setSemantic(semantic);

    return instr;
}

void Disassemble::relocateInstruction(cs_insn *instr, address_t newAddress) {
    instr->address = newAddress;
}
