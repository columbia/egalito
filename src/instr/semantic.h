#ifndef EGALITO_INSTR_SEMANTIC_H
#define EGALITO_INSTR_SEMANTIC_H

#include <utility>  // for std::move
#include <capstone/capstone.h>  // for cs_insn
#include "assembly.h"
#include "storage.h"
#include "visitor.h"
#include "types.h"

class Link;

/** Abstract base class for per-instruction data.

    The getAssembly() method provides details of the instruction operands etc,
    and the Assembly content will be created on the fly if necessary.
*/
class InstructionSemantic {
public:
    virtual ~InstructionSemantic() {}

    virtual const std::string &getData() const = 0;
    virtual size_t getSize() const = 0;

    virtual Link *getLink() const = 0;
    virtual void setLink(Link *newLink) = 0;

    virtual InstructionStorage::AssemblyPtr getAssembly() = 0;

    virtual void accept(InstructionVisitor *visitor) = 0;
};

class SemanticImpl : public InstructionSemantic {
private:
    InstructionStorage storage;
public:
    virtual const std::string &getData() const { return storage.getData(); }
    virtual size_t getSize() const { return storage.getSize(); }

    virtual InstructionStorage::AssemblyPtr getAssembly()
        { return storage.getAssembly(0x0); }
    virtual void setAssembly(InstructionStorage::AssemblyPtr assembly)
        { storage.setAssembly(assembly); }
protected:
    InstructionStorage *getStorage() { return &storage; }
};

template <typename BaseType>
class LinkDecorator : public BaseType {
private:
    Link *link;
public:
    LinkDecorator() : link(nullptr) {}

    virtual Link *getLink() const { return link; }
    virtual void setLink(Link *link) { this->link = link; }
};

#endif
