#ifndef EGALITO_INSTR_SEMANTIC_H
#define EGALITO_INSTR_SEMANTIC_H

#include <string>
#include <utility>  // for std::move
#include <capstone/capstone.h>  // for cs_insn
#include "assembly.h"
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

    virtual Assembly *getAssembly() = 0;
};

class RawByteStorage {
private:
    std::string rawData;
public:
    RawByteStorage(const std::string &rawData) : rawData(rawData) {}

    size_t getSize() const { return rawData.size(); }

    void writeTo(char *target);
    void writeTo(std::string &target);
    std::string getData();

    Assembly *getAssembly() { return nullptr; }
};

/** Stores a complete copy of the capstone data for an instruction.

    This involves allocating memory for capstone details, so this class
    has its copy constructor disabled and can only be moved.
*/
class DisassembledStorage {
private:
    Assembly assembly;
private:
    DisassembledStorage(const DisassembledStorage &other);
    DisassembledStorage &operator = (DisassembledStorage &other);
public:
    DisassembledStorage(const Assembly &assembly)
        : assembly(assembly) {}
    DisassembledStorage(DisassembledStorage &&other);
    ~DisassembledStorage();

    DisassembledStorage &operator = (DisassembledStorage &&other);

    size_t getSize() const { return assembly.getSize(); }

    void writeTo(char *target);
    void writeTo(std::string &target);
    std::string getData();

    Assembly *getAssembly() { return &assembly; }
};

template <typename Storage>
class SemanticImpl : public InstructionSemantic {
private:
    Storage storage;
public:
    SemanticImpl(Storage &&storage) : storage(std::move(storage)) {}

    Storage &getStorage() { return storage; }
    Storage &&moveStorageFrom() { return std::move(storage); }

    virtual size_t getSize() const { return storage.getSize(); }
    virtual void setSize(size_t value)
        { throw "Can't set size for this instruction type!"; }

    virtual Link *getLink() const { return nullptr; }
    virtual void setLink(Link *newLink)
        { throw "Can't set link for this instruction type!"; }

    virtual void writeTo(char *target) { storage.writeTo(target); }
    virtual void writeTo(std::string &target) { storage.writeTo(target); }
    virtual std::string getData() { return storage.getData(); }

    virtual Assembly *getAssembly() { return storage.getAssembly(); }
protected:
    void setStorage(Storage &&storage) { this->storage = std::move(storage); }
};

template <typename BaseType>
class LinkDecorator : public BaseType {
private:
    Link *link;
public:
    LinkDecorator() : link(nullptr) {}

    template <typename Storage>
    LinkDecorator(Storage &&storage) : BaseType(std::move(storage)) {}

    virtual Link *getLink() const { return link; }
    virtual void setLink(Link *link) { this->link = link; }
};

#endif
