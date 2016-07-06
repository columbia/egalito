#include <iostream>  // for debugging
#include <cstring>
#include <capstone/x86.h>
#include "disassemble.h"
#include "elf/symbol.h"
#include "chunk/chunk.h"

Disassemble::Handle::Handle(bool detailed) {
    if(cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        throw "Can't initialize capstone handle!";
    }

    cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);  // AT&T syntax
    if(detailed) {
        cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    }
}

Disassemble::Handle::~Handle() {
    cs_close(&handle);
}

void Disassemble::printInstruction(cs_insn *instr, const char *name,
    long offset) {

    if(name) {
        std::printf("0x%08lx:\t%s\t\t%s <%s>\n",
            instr->address, instr->mnemonic, instr->op_str, name);
    }
    else {
        std::printf("0x%08lx:\t%s\t\t%s\n",
            instr->address, instr->mnemonic, instr->op_str);
    }

#if 0
    std::printf("    ");
    for(int i = 0; i < instr->size; i ++) {
        std::printf("%02x ", (unsigned)instr->bytes[i] & 0xff);
    }
    std::printf("\n");
#endif
}

void Disassemble::printInstructionAtOffset(cs_insn *instr, size_t offset) {
    std::printf("0x%08lx <+%d>:\t%s\t\t%s\n",
        instr->address, (int)offset, instr->mnemonic, instr->op_str);
}

void Disassemble::debug(const uint8_t *code, size_t length,
    address_t realAddress, SymbolList *symbolList) {

    Handle handle(symbolList != 0);
    cs_insn *insn;
    size_t count = cs_disasm(handle.raw(), code, length, realAddress, 0, &insn);
    if(count == 0) {
        std::printf("# empty\n");
        return;
    }
    for(size_t j = 0; j < count; j++) {
        const char *name = 0;
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

        printInstruction(&insn[j], name);
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
    Block *block = new Block();

    for(size_t j = 0; j < count; j++) {
        auto instr = block->append(Instruction(insn[j]));
        instr->setRelativeTo(block);

        bool split = false;
        if(cs_insn_group(handle.raw(), &insn[j], X86_GRP_JUMP)) {
            split = true;
        }
        else if(cs_insn_group(handle.raw(), &insn[j], X86_GRP_CALL)) {
            split = true;
        }
        else if(cs_insn_group(handle.raw(), &insn[j], X86_GRP_RET)) {
            split = true;
        }
        else if(cs_insn_group(handle.raw(), &insn[j], X86_GRP_INT)) {
        }
        else if(cs_insn_group(handle.raw(), &insn[j], X86_GRP_IRET)) {
        }

        cs_detail *detail = insn[j].detail;
        cs_x86 *x = &detail->x86;
        if(x->op_count > 0) {
            for(size_t p = 0; p < x->op_count; p ++) {
                cs_x86_op *op = &x->operands[p];
                if(op->type == X86_OP_IMM) {
                    std::printf("    immediate operand in ");
                    printInstruction(&insn[j]);

                    if(insn[j].id == X86_INS_CALL) {
                        unsigned long imm = op->imm;
                        std::printf("        call\n");
                        instr->makeLink(
                            insn[j].size - 4,
                            new OriginalPosition(imm));
                    }
                }
            }
        }

        if(split) {
            function->append(block);
            block->setRelativeTo(function);
            block = new Block();
        }
    }

    if(block->getSize() == 0) {
        delete block;
    }
    else {
        std::printf("fall-through function [%s]... "
            "adding basic block\n", symbol->getName());
        function->append(block);
        block->setRelativeTo(function);
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
