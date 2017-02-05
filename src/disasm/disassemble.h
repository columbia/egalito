#ifndef EGALITO_DISASM_DISASSEMBLE_H
#define EGALITO_DISASM_DISASSEMBLE_H

#include <climits>  // for INT_MIN
#include <capstone/capstone.h>
#include "types.h"
#include "chunk/chunk.h"
#include "chunk/concrete.h"

class Symbol;
class SymbolList;

class Disassemble {
private:
    class Handle {
    private:
        csh handle;
    public:
        Handle(bool detailed = false);
        ~Handle();

        csh &raw() { return handle; }
    };
public:
    static void debug(const uint8_t *code, size_t length,
        address_t realAddress = 0, SymbolList *symbolList = 0);

    static Function *function(Symbol *symbol, address_t baseAddr,
        SymbolList *symbolList = 0);
    static cs_insn getInsn(const std::vector<unsigned char> &str, address_t address = 0);
    static Instruction *instruction(const std::vector<unsigned char> &bytes,
        bool details = true, address_t address = 0);
    static Instruction *instruction(cs_insn *ins, Handle &handle,
        bool details = true);
};

#endif
