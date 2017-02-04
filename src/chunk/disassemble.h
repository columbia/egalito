#ifndef EGALITO_DISASSEMBLE_H
#define EGALITO_DISASSEMBLE_H

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
    static std::string formatBytes(const char *bytes, size_t size);
    static void printInstruction(cs_insn *instr,
        int offset = INT_MIN, const char *name = 0);
    static void printInstructionRaw(unsigned long address,
        int offset, const char *opcode, unsigned long target,
        const char *name = 0, const std::string &rawDisasm = "");
    static void printInstructionRaw(unsigned long address,
        int offset, const char *opcode, const char *args,
        const char *name, const std::string &rawDisasm);
public:
    static void debug(const uint8_t *code, size_t length,
        address_t realAddress = 0, SymbolList *symbolList = 0);

    static Function *function(Symbol *symbol, address_t baseAddr,
        SymbolList *symbolList = 0);
    static cs_insn getInsn(std::string str, address_t address = 0);
    static cs_insn getInsn(const std::vector<unsigned char> &str, address_t address = 0);
    static Instruction *instruction(const std::vector<unsigned char> &bytes,
        bool details = true, address_t address = 0);

    static void relocateInstruction(cs_insn *instr, address_t newAddress);
};

#endif
