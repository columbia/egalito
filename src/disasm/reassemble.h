#ifndef EGALITO_DISASM_REASSEMBLE_H
#define EGALITO_DISASM_REASSEMBLE_H

#ifdef USE_KEYSTONE

#include <unordered_map>
#include <vector>
#include <string>


class Instruction;

class Reassemble {
public:
    using Opcode = std::vector<unsigned char>;
    using OpcodeList = std::vector<Opcode>;
    using InstructionList = std::vector<Instruction *>;

    /**
        We use semicolon seperated string
    */
    static InstructionList instructions(const std::string &str);

    /**
        The string must contain a single instruction
    */
    static Instruction* instruction(const std::string &str);

    static OpcodeList opcodes(const std::string &str);

    static Opcode opcode(const std::string &str);
};

/*
class Snippet {
    friend class ChunkMutator;
private:
    std::vector<Opcode> opcodes;
public:
    Snippet(const std::string &str);
};

*/
class ReassemblerCache {
private:
    std::unordered_map<std::string, Reassemble::Opcode> cache;
public:
    void set(const std::string& str, const Reassemble::Opcode& opcode) {
        this->cache[str] = opcode;
    }

    Reassemble::Opcode get(const std::string &str);
};

#endif  // USE_KEYSTONE
#endif
