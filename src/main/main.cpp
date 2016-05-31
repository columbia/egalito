#include <iostream>
#include <iomanip>
#include <cstdio>
#include "main.h"
#include "elf/elfmap.h"
#include "elf/symbol.h"
#include <capstone/x86.h>

void disassemble(const uint8_t *code, size_t length, address_t realAddress,
    SymbolList *symbolList);

int main(int argc, char *argv[]) {
    if(argc > 1) {
        try {
            ElfMap elf(argv[1]);
            SymbolList symbolList = SymbolList::buildSymbolList(&elf);

            auto baseAddr = elf.getCopyBaseAddress();
            for(auto s : symbolList) {
                auto sym = s.second;
                std::cout << "---[" << sym->getName() << "]---\n";
                auto addr = sym->getAddress();
                std::cout << "addr " << std::hex << addr
                    << " -> " << std::hex << addr + baseAddr << "\n";
                disassemble((uint8_t *)(addr + baseAddr), sym->getSize(), addr,
                    &symbolList);
            }
        }
        catch(const char *s) {
            std::cerr << "Error: " << s;
        }
    }
}

void disassemble(const uint8_t *code, size_t length, address_t realAddress,
    SymbolList *symbolList) {

    csh handle;
    cs_insn *insn;

    if(cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        return;
    }

    cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);  // AT&T syntax
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);  // turn on detailed data

    size_t count = cs_disasm(handle, code, length, realAddress, 0, &insn);
    if(count > 0) {
        for(size_t j = 0; j < count; j++) {
            const char *name = 0;
            if(insn[j].id == X86_INS_CALL) {
                cs_x86_op *op = &insn[j].detail->x86.operands[0];
                if(op->type == X86_OP_IMM) {
                    unsigned long imm = op->imm;
                    auto sym = symbolList->find(imm);
                    if(sym) {
                        name = sym->getName();
                    }
                }
            }

            if(name) {
                std::printf("0x%08lx:\t%s\t\t%s\t# <%s>\n", insn[j].address, insn[j].mnemonic,
                    insn[j].op_str, name);
            }
            else {
                std::printf("0x%08lx:\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,
                    insn[j].op_str);
            }
        }

        cs_free(insn, count);
    }
    else std::printf("ERROR: Failed to disassemble given code!\n");

    cs_close(&handle);
}
