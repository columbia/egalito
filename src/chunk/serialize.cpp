#include <cstring>
#include <cstdint>
#include <cassert>
#include <sstream>
#include <functional>
#include "serialize.h"
#include "chunk.h"
#include "concrete.h"
#include "visitor.h"
#include "archive/archive.h"
#include "archive/reader.h"
#include "archive/writer.h"
#include "archive/stream.h"
#include "log/log.h"

#include "serializer.h"

#if 1
void ChunkSerializer::serialize(Chunk *chunk, std::string filename) {
    EgalitoArchive *archive = new EgalitoArchive();
    ChunkSerializerOperations op(archive);

    op.serialize(chunk);

    EgalitoArchiveWriter(archive).write(filename);

    delete archive;
}

Chunk *ChunkSerializer::deserialize(std::string filename) {
    LOG(1, "::deserialize " << filename);
    LOG(1, "::deserialize make archive");
    EgalitoArchive *archive = EgalitoArchiveReader().read(filename);
    ChunkSerializerOperations op(archive);

    LOG(1, "::deserialize instantiations");
    for(auto flat : archive->getFlatList()) {
        flat->setInstance(op.instantiate(flat));
    }

    LOG(1, "::deserialize deserialize() calls");
    for(auto flat : archive->getFlatList()) {
        op.deserialize(flat);
    }

    LOG(1, "::deserialize done");

    auto root = op.lookup(0);
    delete archive;
    return root;
}
#else
class SerializeImpl : public ChunkListener {
private:
    EgalitoArchive *archive;
public:
    SerializeImpl(EgalitoArchive *archive) : archive(archive) {}
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
    FlatChunk *flat = archive->getFlatList().newFlatChunk(
        EgalitoArchive::TYPE_Program);
    BufferedStreamWriter writer(flat);

    for(auto module : CIter::children(program)) {
        writer.write(static_cast<uint32_t>(archive->getFlatList().getCount()));
        module->accept(this);
    }
}

void SerializeImpl::visit(Module *module) {
    FlatChunk *flat = archive->getFlatList().newFlatChunk(
        EgalitoArchive::TYPE_Module);
    {
        BufferedStreamWriter writer(flat);
        writer.write(static_cast<uint32_t>(archive->getFlatList().getCount()));  // FunctionList id
        writer.writeAnyLength(module->getName());
    }

    module->getFunctionList()->accept(this);
}

void SerializeImpl::visit(FunctionList *functionList) {
    FlatChunk *flat = archive->getFlatList().newFlatChunk(
        EgalitoArchive::TYPE_FunctionList);
    {
        BufferedStreamWriter writer(flat);
        writer.write(static_cast<uint32_t>(functionList->getChildren()
            ->getIterable()->getCount()));

        int i = 0;
        for(auto function : CIter::children(functionList)) {
            writer.write(static_cast<uint32_t>(archive->getFlatList().getCount() + i));
            i ++;
        }
    }

    for(auto function : CIter::children(functionList)) {
        function->accept(this);
    }
}

void SerializeImpl::visit(Function *function) {
    FlatChunk *flat = archive->getFlatList().newFlatChunk(
        EgalitoArchive::TYPE_Function);
    BufferedStreamWriter writer(flat);

    writer.write(static_cast<uint64_t>(function->getAddress()));
    writer.writeAnyLength(function->getName());
}

class DeserializeImpl {
private:
    EgalitoArchive *archive;
public:
    DeserializeImpl(EgalitoArchive *archive) : archive(archive) {}
    void instantiate(FlatChunk *flat);
    Chunk *parse(FlatChunk *flat);
private:
    typedef Chunk *(DeserializeImpl::*ChunkBuilder)(FlatChunk *flat,
        ArchiveStreamReader &reader);
    Chunk *makeProgram(FlatChunk *flat, ArchiveStreamReader &reader);
    Chunk *makeModule(FlatChunk *flat, ArchiveStreamReader &reader);
    Chunk *makeFunctionList(FlatChunk *flat, ArchiveStreamReader &reader);
    Chunk *makeFunction(FlatChunk *flat, ArchiveStreamReader &reader);
    Chunk *notYetImplemented(FlatChunk *flat, ArchiveStreamReader &reader);
};

void DeserializeImpl::instantiate(FlatChunk *flat) {
    std::function<Chunk *()> constructor[] = {
        [] () -> Chunk* { return nullptr; },              // TYPE_UNKNOWN
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

    assert(flat != nullptr);
    const auto &type = flat->getType();
    assert(type < sizeof(constructor)/sizeof(*constructor));

    Chunk *instance = (constructor[type])();
    flat->setInstance(instance);
}

Chunk *DeserializeImpl::parse(FlatChunk *flat) {
    static const ChunkBuilder decoder[] = {
        &DeserializeImpl::notYetImplemented,    // TYPE_UNKNOWN
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

    assert(flat != nullptr);
    const auto &type = flat->getType();
    assert(type < sizeof(decoder)/sizeof(*decoder));

    std::istringstream stream(flat->getData());
    ArchiveStreamReader reader(stream);

    Chunk *result = (this->*decoder[type])(flat, reader);
    return result;
}

Chunk *DeserializeImpl::makeProgram(FlatChunk *flat, ArchiveStreamReader &reader) {
    uint32_t id;
    reader.read(id);

    flat->getInstance<Program>()->getChildren()->add(
        archive->getFlatList().get(id)->getInstance<Module>());

    return flat->getInstance<Program>();
}

Chunk *DeserializeImpl::makeModule(FlatChunk *flat, ArchiveStreamReader &reader) {
    uint32_t id;
    reader.read(id);
    std::string name;
    reader.readAnyLength(name);

    LOG(1, "trying to parse Module [" << name << "]");

    auto functionList = archive->getFlatList().get(id)->getInstance<FunctionList>();
    flat->getInstance<Module>()->getChildren()->add(functionList);
    flat->getInstance<Module>()->setFunctionList(functionList);

    return flat->getInstance<Module>();
}

Chunk *DeserializeImpl::makeFunctionList(FlatChunk *flat, ArchiveStreamReader &reader) {
    uint32_t count;
    reader.read(count);

    for(uint32_t i = 0; i < count; i ++) {
        uint32_t id;
        reader.read(id);
        flat->getInstance<FunctionList>()->getChildren()->add(
            archive->getFlatList().get(id)->getInstance<Function>());
    }

    return flat->getInstance<FunctionList>();
}

Chunk *DeserializeImpl::makeFunction(FlatChunk *flat, ArchiveStreamReader &reader) {
    uint64_t address;
    std::string name;
    reader.read(address);
    reader.readAnyLength(name);

    flat->getInstance<FuzzyFunction>()->setPosition(new AbsolutePosition(address));
    flat->getInstance<FuzzyFunction>()->setName(name);

    return flat->getInstance<FuzzyFunction>();
}

Chunk *DeserializeImpl::notYetImplemented(FlatChunk *flat, ArchiveStreamReader &reader) {
    LOG(1, "WARNING: not yet implemented: deserialize archive chunk type "
        << flat->getType());
    return nullptr;
}

void ChunkSerializer::serialize(Chunk *chunk, std::string filename) {
    EgalitoArchive *archive = new EgalitoArchive();
    SerializeImpl serializer(archive);
    chunk->accept(&serializer);

    EgalitoArchiveWriter(archive).write(filename);

    delete archive;
}

Chunk *ChunkSerializer::deserialize(std::string filename) {
    EgalitoArchive *archive = EgalitoArchiveReader().read(filename);
    DeserializeImpl deserializer(archive);

    std::vector<Chunk *> chunkList;

    for(auto flat : archive->getFlatList()) {
        deserializer.instantiate(flat);
    }

    for(auto flat : archive->getFlatList()) {
        Chunk *chunk = deserializer.parse(flat);
        chunkList.push_back(chunk);
    }

    delete archive;
    return chunkList.size() ? chunkList[0] : nullptr;
}
#endif
