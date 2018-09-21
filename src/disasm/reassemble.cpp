#ifdef USE_KEYSTONE
#include <keystone/keystone.h>
#include <sstream>
#include <cstdlib>
#include "log/log.h"
#include "disasm/disassemble.h"
#include "disasm/reassemble.h"

// cache the keystone library object
static ks_engine *ks = nullptr;

// cache the compiled individual instructions
static ReassemblerCache reassembleCache;

template<typename Out>
static void split(const std::string &s, char delim, Out result) {
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, delim)) {
        *(result++) = item;
    }
}

static std::vector<std::string> split(const std::string &s, char delim) {
    std::vector<std::string> elems;
    split(s, delim, std::back_inserter(elems));
    return elems;
}

Instruction *Reassemble::instruction(const std::string &str) {
    auto compiledOpcode = opcode(str);
    return Disassemble::instruction(compiledOpcode);
}

Reassemble::InstructionList Reassemble::instructions(const std::string &str) {
    auto compiledOpcodes = opcodes(str);
    InstructionList ret;

    for (auto& op: compiledOpcodes) {
        Instruction* instr = Disassemble::instruction(op);
        ret.push_back(instr);
    }

    return ret;
}

Reassemble::Opcode Reassemble::opcode(const std::string &s) {
    if (!ks) {
        // TODO remains to be done for ARM
        auto err = ks_open(KS_ARCH_X86, KS_MODE_64, &ks);
        if (err != KS_ERR_OK) {
            LOG(0, "Cannot load keystone library!");
            std::abort();
        }

        ks_option(ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_ATT);
    }
    unsigned char *encode;
    size_t size, count;
    if (ks_asm(ks, s.c_str(), 0, &encode, &size, &count) != KS_ERR_OK) {
        LOG(0, "ERROR: ks_asm() failed" << ks_errno(ks));
        LOG(0, "Keystone was trying to compile [" << s << "]");
        std::abort();
    } else {
        for (size_t i = 0; i < size; i++) {
            LOG(10, encode[i]);
        }
        LOG(0, "Keystone: compiled " << size << " bytes");
    }

    Opcode ret(encode, encode + size);
    return ret;
}

Reassemble::OpcodeList Reassemble::opcodes(const std::string& str) {
    std::vector<std::string> statements;
    statements = split(str, '\n');

    OpcodeList ret;

    for (std::string& stmt: statements) {
        Opcode op = reassembleCache.get(stmt);

        if (op.size() > 0) ret.push_back(op);
        else {
            Opcode compiledOp = opcode(stmt);
            ret.push_back(compiledOp);
            reassembleCache.set(stmt, compiledOp);
        }
    }

    return ret;
}


Reassemble::Opcode ReassemblerCache::get(const std::string &str) {
    if (this->cache.count(str) > 0) {
        return this->cache[str];
    } else {
        return Reassemble::Opcode();
    }
}
#endif
