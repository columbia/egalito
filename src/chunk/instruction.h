#ifndef EGALITO_CHUNK_INSTRUCTION_H
#define EGALITO_CHUNK_INSTRUCTION_H

#include <string>
#include <capstone/capstone.h>  // for cs_insn
#include "types.h"

class Instruction;
class Link;

/** Abstract base class for special instruction data.
*/
class InstructionSemantic {
public:
    virtual ~InstructionSemantic() {}

    virtual size_t getSize() const = 0;
    virtual void setSize(size_t value) = 0;

    virtual Link *getLink() const = 0;
    virtual void setLink(Link *newLink) = 0;

    virtual void writeTo(char *target) = 0;
    virtual void writeTo(std::string &target) = 0;
    virtual std::string getData() = 0;

    virtual cs_insn *getCapstone() = 0;
};

#if 0
class Storage {
public:
    virtual ~Storage() {}

    virtual size_t getSize() const = 0;

    virtual void writeTo(char *target) = 0;
    virtual void writeTo(std::string &target) = 0;
    virtual std::string getData() const = 0;
};

class RawByteStorage : public Storage {
private:
    std::string rawData;
public:
    RawByteStorage(const std::string &rawData) : rawData(rawData) {}

    virtual size_t getSize() const { return rawData.size(); }

    virtual void writeTo(char *target);
    virtual void writeTo(std::string &target);
    virtual std::string getData() const;
};

class DisassembledStorage : public Storage {
private:
    cs_insn insn;
public:
    DisassembledStorage(const cs_insn &insn) : insn(insn) {}

    virtual size_t getSize() const { return insn.size; }

    virtual void writeTo(char *target);
    virtual void writeTo(std::string &target);
    virtual std::string getData() const;
};
#else
class RawByteStorage {
private:
    std::string rawData;
public:
    RawByteStorage(const std::string &rawData) : rawData(rawData) {}

    size_t getSize() const { return rawData.size(); }

    void writeTo(char *target);
    void writeTo(std::string &target);
    std::string getData();

    cs_insn *getCapstone() { return nullptr; }
};

class DisassembledStorage {
private:
    cs_insn insn;
public:
    DisassembledStorage(const cs_insn &insn) : insn(insn) {}

    size_t getSize() const { return insn.size; }

    void writeTo(char *target);
    void writeTo(std::string &target);
    std::string getData();

    cs_insn *getCapstone() { return &insn; }
};
#endif

template <typename Storage>
class SemanticImpl : public InstructionSemantic {
private:
    Storage storage;
public:
    SemanticImpl(const Storage &storage) : storage(storage) {}

    Storage &getStorage() { return storage; }

    virtual size_t getSize() const { return storage.getSize(); }
    virtual void setSize(size_t value)
        { throw "Can't set size for this instruction type!"; }

    virtual Link *getLink() const { return nullptr; }
    virtual void setLink(Link *newLink)
        { throw "Can't set link for this instruction type!"; }

    virtual void writeTo(char *target) { storage.writeTo(target); }
    virtual void writeTo(std::string &target) { storage.writeTo(target); }
    virtual std::string getData() { return storage.getData(); }

    virtual cs_insn *getCapstone() { return storage.getCapstone(); }
};

template <typename BaseType>
class LinkDecorator : public BaseType {
private:
    Link *link;
public:
    LinkDecorator() : link(nullptr) {}

    template <typename Storage>
    LinkDecorator(const Storage &storage) : BaseType(storage) {}

    virtual Link *getLink() const { return link; }
    virtual void setLink(Link *link) { this->link = link; }
};

// --- concrete classes follow ---

typedef SemanticImpl<RawByteStorage> RawInstruction;
typedef SemanticImpl<DisassembledStorage> DisassembledInstruction;
typedef LinkDecorator<SemanticImpl<DisassembledStorage>> RelocationInstruction;

class ControlFlowInstruction : public LinkDecorator<InstructionSemantic> {
private:
    Instruction *source;
    std::string opcode;
    std::string mnemonic;
    int displacementSize;
public:
    ControlFlowInstruction(Instruction *source, std::string opcode, std::string mnemonic, int displacementSize)
        : source(source), opcode(opcode), mnemonic(mnemonic), displacementSize(displacementSize) {}

    virtual size_t getSize() const { return opcode.size() + displacementSize; }
    virtual void setSize(size_t value);

    virtual void writeTo(char *target);
    virtual void writeTo(std::string &target);
    virtual std::string getData();

    virtual cs_insn *getCapstone() { return nullptr; }

    Instruction *getSource() const { return source; }
    std::string getMnemonic() const { return mnemonic; }
private:
    diff_t calculateDisplacement();
};

#endif
