#include <cstring>
#include <cstdint>
#include <cassert>
#include <sstream>
#include <functional>
#include "serialize.h"
#include "chunk.h"
#include "concrete.h"
#include "visitor.h"
#include "archive/generic.h"
#include "archive/reader.h"
#include "archive/writer.h"
#include "archive/flatchunk.h"
#include "archive/stream.h"
#include "log/log.h"

class SerializeImpl : public ChunkListener {
private:
    EgalitoArchiveWriter &archive;
public:
    SerializeImpl(EgalitoArchiveWriter &archive) : archive(archive) {}
    virtual void visit(Program *program);
    virtual void visit(Module *module);
    virtual void visit(FunctionList *functionList);
    //virtual void visit(PLTList *pltList);
    //virtual void visit(JumpTableList *jumpTableList);
    //virtual void visit(DataRegionList *dataRegionList);
    virtual void visit(Function *function);
    //virtual void visit(Block *block);
    //virtual void visit(Instruction *instruction);
    //virtual void visit(PLTTrampoline *instruction);
    //virtual void visit(JumpTable *jumpTable);
    //virtual void visit(JumpTableEntry *jumpTableEntry);
    //virtual void visit(DataRegion *dataRegion);
};

void SerializeImpl::visit(Program *program) {
    archive.getFlatList().newFlatChunk(EgalitoArchive::TYPE_Program);
    archive.getFlatList().append32(archive.getFlatList().getCount());  // 1st module

    for(auto module : CIter::children(program)) {
        module->accept(this);
    }
}

void SerializeImpl::visit(Module *module) {
    archive.getFlatList().newFlatChunk(EgalitoArchive::TYPE_Module);
    archive.getFlatList().append32(archive.getFlatList().getCount());  // function list

    std::ostringstream stream;
    ArchiveStreamWriter writer(stream);

    writer.writeAnyLength(module->getName());

    archive.getFlatList().appendData(stream.str());

    module->getFunctionList()->accept(this);
}

void SerializeImpl::visit(FunctionList *functionList) {
    archive.getFlatList().newFlatChunk(EgalitoArchive::TYPE_FunctionList);
    archive.getFlatList().append32(functionList->getChildren()
        ->getIterable()->getCount());

    int i = 0;
    for(auto function : CIter::children(functionList)) {
        archive.getFlatList().append32(archive.getFlatList().getCount() + i);
        i ++;
    }

    for(auto function : CIter::children(functionList)) {
        function->accept(this);
    }
}

void SerializeImpl::visit(Function *function) {
    archive.getFlatList().newFlatChunk(EgalitoArchive::TYPE_Function);

    std::ostringstream stream;
    ArchiveStreamWriter writer(stream);

    writer.write(static_cast<uint64_t>(function->getAddress()));
    writer.writeAnyLength(function->getName());

    archive.getFlatList().appendData(stream.str());
}

class DeserializeImpl {
private:
    EgalitoArchiveReader &archive;
public:
    DeserializeImpl(EgalitoArchiveReader &archive) : archive(archive) {}
    void instantiate(FlatChunk &flat);
    Chunk *parse(const FlatChunk &flat);
private:
    typedef Chunk *(DeserializeImpl::*ChunkBuilder)(const FlatChunk &flat);
    Chunk *makeProgram(const FlatChunk &flat);
    Chunk *makeModule(const FlatChunk &flat);
    Chunk *makeFunctionList(const FlatChunk &flat);
    Chunk *makeFunction(const FlatChunk &flat);
    Chunk *notYetImplemented(const FlatChunk &flat);
};

void DeserializeImpl::instantiate(FlatChunk &flat) {
    std::function<Chunk *()> constructor[] = {
        [] () -> Chunk* { return new Program(nullptr); },        // TYPE_Program
        [] () -> Chunk* { return new Module(); },         // TYPE_Module
#if 0
        [] () -> Chunk* { return new FunctionList(); },   // TYPE_FunctionList
        [] () -> Chunk* { return new PLTList(); },        // TYPE_PLTList
        [] () -> Chunk* { return new JumpTableList(); },  // TYPE_JumpTableList
        [] () -> Chunk* { return new DataRegionList(); }, // TYPE_DataRegionList
        [] () -> Chunk* { return new FuzzyFunction(); },       // TYPE_Function
        [] () -> Chunk* { return new Block(); },          // TYPE_Block
        [] () -> Chunk* { return new Instruction(); },    // TYPE_Instruction
        [] () -> Chunk* { return new PLTTrampoline(); },  // TYPE_PLTTrampoline
        [] () -> Chunk* { return new JumpTable(); },      // TYPE_JumpTable
        [] () -> Chunk* { return new JumpTableEntry(); }, // TYPE_JumpTableEntry
        [] () -> Chunk* { return new DataRegion(); },     // TYPE_DataRegion
        [] () -> Chunk* { return new DataSection(); },    // TYPE_DataSection
        [] () -> Chunk* { return new DataVariable(); },   // TYPE_DataVariable
        [] () -> Chunk* { return new MarkerList(); },     // TYPE_MarkerList
        [] () -> Chunk* { return new Marker(); },         // TYPE_Marker
#else
        [] () -> Chunk* { return new FunctionList(); },   // TYPE_FunctionList
        [] () -> Chunk* { return nullptr; },
        [] () -> Chunk* { return nullptr; },
        [] () -> Chunk* { return nullptr; },
        [] () -> Chunk* { return new FuzzyFunction(); },       // TYPE_Function
        [] () -> Chunk* { return nullptr; },
        [] () -> Chunk* { return nullptr; },
        [] () -> Chunk* { return nullptr; },
        [] () -> Chunk* { return nullptr; },
        [] () -> Chunk* { return nullptr; },
        [] () -> Chunk* { return nullptr; },
        [] () -> Chunk* { return nullptr; },
        [] () -> Chunk* { return nullptr; },
        [] () -> Chunk* { return nullptr; },
        [] () -> Chunk* { return nullptr; },
#endif
    };

    const auto &type = flat.getType();
    assert(type < sizeof(constructor)/sizeof(*constructor));

    Chunk *instance = (constructor[type])();
    flat.setInstance(instance);
}

Chunk *DeserializeImpl::parse(const FlatChunk &flat) {
    static const ChunkBuilder decoder[] = {
        &DeserializeImpl::makeProgram,          // TYPE_Program
        &DeserializeImpl::makeModule,           // TYPE_Module
        &DeserializeImpl::makeFunctionList,     // TYPE_FunctionList
        &DeserializeImpl::notYetImplemented,    // TYPE_PLTList
        &DeserializeImpl::notYetImplemented,    // TYPE_JumpTableList
        &DeserializeImpl::notYetImplemented,    // TYPE_DataRegionList
        &DeserializeImpl::makeFunction,         // TYPE_Function
        &DeserializeImpl::notYetImplemented,    // TYPE_Block
        &DeserializeImpl::notYetImplemented,    // TYPE_Instruction
        &DeserializeImpl::notYetImplemented,    // TYPE_PLTTrampoline
        &DeserializeImpl::notYetImplemented,    // TYPE_JumpTable
        &DeserializeImpl::notYetImplemented,    // TYPE_JumpTableEntry
        &DeserializeImpl::notYetImplemented,    // TYPE_DataRegion
        &DeserializeImpl::notYetImplemented,    // TYPE_DataSection
        &DeserializeImpl::notYetImplemented,    // TYPE_DataVariable
        &DeserializeImpl::notYetImplemented,    // TYPE_MarkerList
        &DeserializeImpl::notYetImplemented,    // TYPE_Marker
    };

    const auto &type = flat.getType();
    assert(type < sizeof(decoder)/sizeof(*decoder));

    Chunk *result = (this->*decoder[type])(flat);
    return result;
}

Chunk *DeserializeImpl::makeProgram(const FlatChunk &flat) {
    std::istringstream stream(flat.getData());
    ArchiveStreamReader reader(stream);

    uint32_t id;
    reader.read(id);

    flat.getInstance<Program>()->getChildren()->add(
        archive.getFlatList().get(id).getInstance<Module>());

    return flat.getInstance<Program>();
}

Chunk *DeserializeImpl::makeModule(const FlatChunk &flat) {
    std::istringstream stream(flat.getData());
    ArchiveStreamReader reader(stream);

    uint32_t id;
    reader.read(id);
    std::string name;
    reader.readAnyLength(name);

    LOG(1, "trying to parse Module [" << name << "]");

    auto functionList = archive.getFlatList().get(id).getInstance<FunctionList>();
    flat.getInstance<Module>()->getChildren()->add(functionList);
    flat.getInstance<Module>()->setFunctionList(functionList);

    return flat.getInstance<Module>();
}

Chunk *DeserializeImpl::makeFunctionList(const FlatChunk &flat) {
    std::istringstream stream(flat.getData());
    ArchiveStreamReader reader(stream);

    uint32_t count;
    reader.read(count);

    for(uint32_t i = 0; i < count; i ++) {
        uint32_t id;
        reader.read(id);
        flat.getInstance<FunctionList>()->getChildren()->add(
            archive.getFlatList().get(id).getInstance<Function>());
    }

    return flat.getInstance<FunctionList>();
}

Chunk *DeserializeImpl::makeFunction(const FlatChunk &flat) {
    std::istringstream stream(flat.getData());
    ArchiveStreamReader reader(stream);

    uint64_t address;
    std::string name;
    reader.read(address);
    reader.readAnyLength(name);

    flat.getInstance<FuzzyFunction>()->setPosition(new AbsolutePosition(address));
    flat.getInstance<FuzzyFunction>()->setName(name);

    return flat.getInstance<FuzzyFunction>();
}

Chunk *DeserializeImpl::notYetImplemented(const FlatChunk &flat) {
    LOG(1, "WARNING: not yet implemented: deserialize archive chunk type "
        << flat.getType());
    return nullptr;
}

void ChunkSerializer::serialize(Chunk *chunk, std::string filename) {
    EgalitoArchiveWriter archive;
    SerializeImpl serializer(archive);
    chunk->accept(&serializer);

    archive.writeTo(filename);
}

Chunk *ChunkSerializer::deserialize(std::string filename) {
    EgalitoArchiveReader archive;
    DeserializeImpl deserializer(archive);

    std::vector<Chunk *> chunkList;

    archive.readFlatList(filename);
    for(auto &flat : archive.getFlatList()) {
        deserializer.instantiate(flat);
    }

    for(const auto &flat : archive.getFlatList()) {
        Chunk *chunk = deserializer.parse(flat);
        chunkList.push_back(chunk);
    }

    return chunkList.size() ? chunkList[0] : nullptr;
}
