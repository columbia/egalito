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

void Disassemble::function(Symbol *symbol, address_t baseAddr,
    SymbolList *symbolList) {

    address_t readAddress = baseAddr + symbol->getAddress();
    address_t trueAddress = symbol->getAddress();
    Handle handle(true);
    cs_insn *insn;
    size_t count = cs_disasm(handle.raw(),
        (const uint8_t *)readAddress, symbol->getSize(),
        trueAddress, 0, &insn);

    Function *func = new Function(symbol, false);
    //Block *block = new Block();

    for(size_t j = 0; j < count; j++) {
        printInstruction(&insn[j]);

        if(cs_insn_group(handle.raw(), &insn[j], X86_GRP_JUMP)) {
            std::printf("---\n");
        }
        else if(cs_insn_group(handle.raw(), &insn[j], X86_GRP_CALL)) {
            std::printf("---\n");
        }
        else if(cs_insn_group(handle.raw(), &insn[j], X86_GRP_RET)) {
            std::printf("---\n");
        }
        else if(cs_insn_group(handle.raw(), &insn[j], X86_GRP_INT)) {
        }
        else if(cs_insn_group(handle.raw(), &insn[j], X86_GRP_IRET)) {
        }
    }

    cs_free(insn, count);
}
