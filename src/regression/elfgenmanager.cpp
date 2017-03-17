#include <iostream>
#include "disasm/disassemble.h"
#include "elfgenmanager.h"
#include "conductor/conductor.h"
#include "transform/generator.h"
#include "log/log.h"

class ChunkWriter : public ChunkVisitor {
private:
    template <typename Type>
    void recurse(Type *root) {
        for(auto child : root->getChildren()->genericIterable()) {
            child->accept(this);
        }
    }
public:
    virtual void visit(Program *program) {}
    virtual void visit(CodePage *codePage) {}
    virtual void visit(Module *module) { recurse(module); }
    virtual void visit(Function *function) { recurse(function); }
    virtual void visit(Block *block) { recurse(block); }
    virtual void visit(Instruction *instruction) {
        address_t address = instruction->getAddress();
        instruction->getSemantic()->writeTo(
            reinterpret_cast<char *>(address));
    }
};

void ElfGenManager::copyCodeToSandbox(Generator *generator) {
    auto chunkList = elfSpace->getModule()->getChildren();
    if(!sandbox || !chunkList) throw "Sandbox, elfspace, or chunklist not set";

#if 0
    for(auto chunk : chunkList->genericIterable()) {
        auto slot = sandbox->allocate(chunk->getSize());
        chunk->getPosition()->set(slot.getAddress());
        auto writer = ChunkWriter();
        chunk->accept(&writer);
        CLOG(1, "ElfBuilder writing [%s] to 0x%lx", chunk->getName().c_str(), slot.getAddress());
    }
#else
    generator->pickAddressesInSandbox(elfSpace->getModule(), sandbox);
    generator->copyCodeToSandbox(elfSpace->getModule(), sandbox);
#endif
}
