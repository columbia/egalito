#include "chunk/disassemble.h"
#include "elfbuilder.h"
#include "log/log.h"
#include <iostream>

void ElfBuilder::buildChunkList() {
    SymbolList *symbolList = elfSpace->getSymbolList();
    if(symbolList == nullptr)
        throw "ElfMap or Symbol List not set";

    ElfChunkList<Function> *functionList = new ElfChunkList<Function>();
    auto baseAddr = elfSpace->getElfMap()->getCopyBaseAddress();
    for(auto sym : *symbolList) {
        Function *function = Disassemble::function(sym, baseAddr, symbolList);
        functionList->add(function);
    }
    elfSpace->setChunkList(functionList);
}

void ElfBuilder::buildSymbolList() {
    if(elfSpace->getElfMap() == nullptr)
        throw "ElfMap not set";

    SymbolList *symbolList = SymbolList::buildSymbolList(elfSpace->getElfMap());
    elfSpace->setSymbolList(symbolList);
}

void ElfBuilder::buildRelocList() {
    if(elfSpace->getElfMap() == nullptr || elfSpace->getSymbolList() == nullptr)
        throw "ElfMap not set";

    RelocList *relocList = RelocList::buildRelocList(elfSpace->getElfMap(), elfSpace->getSymbolList());
    elfSpace->setRelocList(relocList);
}

class ChunkWriter : public ChunkVisitor {
private:
    template <typename Type>
    void recurse(Type *root) {
        for(auto child : root->getChildren()->iterable()) {
            child->accept(this);
        }
    }
public:
    virtual void visit(Program *program) {}
    virtual void visit(CodePage *codePage) {}
    virtual void visit(Function *function) { recurse(function); }
    virtual void visit(Block *block) { recurse(block); }
    virtual void visit(Instruction *instruction) {
        address_t address = instruction->getAddress();
        instruction->getSemantic()->writeTo(
            reinterpret_cast<char *>(address));
    }
};

void ElfBuilder::copyCodeToSandbox() {
    ElfChunkList<Function> *chunkList = elfSpace->getChunkList();
    if(sandbox == nullptr || chunkList == nullptr)
        throw "Sandbox, elfspace, or chunklist not set";

#if 1
    for(auto chunk : chunkList->iterable()) {
        auto slot = sandbox->allocate(chunk->getSize());
        chunk->getPosition()->set(slot.getAddress());
        auto writer = ChunkWriter();
        chunk->accept(&writer);
        CLOG(1, "ElfBuilder writing [%s] to 0x%lx", chunk->getName().c_str(), slot.getAddress());
    }
#endif
}
