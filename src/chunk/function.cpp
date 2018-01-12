#include <sstream>
#include <iomanip>
#include <cstring>
#include "function.h"
#include "serializer.h"
#include "visitor.h"
#include "chunk/cache.h"
#include "elf/symbol.h"
#include "disasm/disassemble.h"
#include "instr/writer.h"
#include "instr/semantic.h"
#include "instr/serializer.h"
#include "operation/mutator.h"
#include "log/log.h"

#include "instr/concrete.h"
#include "dump.h"

#include "log/temp.h"

void Function::makeCache() {
    this->cache = new ChunkCache(this);
}

Function::Function(address_t originalAddress)
    : symbol(nullptr), nonreturn(false), cache(nullptr) {

    std::ostringstream stream;
    stream << "fuzzyfunc-0x" << std::hex << originalAddress;
    name = stream.str();
}

Function::Function(Symbol *symbol)
    : symbol(symbol), nonreturn(false), cache(nullptr) {

    name = symbol->getName();
}

bool Function::hasName(std::string name) const {
    if(!symbol) return false;
    if(symbol->getName() == name) return true;
    for(auto s : symbol->getAliases()) {
        if(std::string(s->getName()) == name) {
            return true;
        }
    }

    return false;
}

void Function::serialize(ChunkSerializerOperations &op,
    ArchiveStreamWriter &writer) {

    LOG(10, "serialize function " << getName());

    writer.write(getAddress());
    writer.writeString(getName());

#if 0  // don't use compression
    writer.writeValue(false);
    op.serializeChildren(this, writer);
#else  // compress data
    writer.writeValue(true);

    //op.serializeChildren(this, writer);  // serialize empty children!
    op.serializeChildrenIDsOnly(this, writer, 2);

    writer.write<uint32_t>(
        this->getChildren()->getIterable()->getCount());
    for(auto block : CIter::children(this)) {
        writer.write<uint32_t>(
            block->getChildren()->getIterable()->getCount());
        for(auto instr : CIter::children(block)) {
#if 1
            InstrSerializer(op).serialize(instr->getSemantic(), writer);
#else
            InstrWriterGetData instrWriter;
            instr->getSemantic()->accept(&instrWriter);
            writer.writeAnyLength(instrWriter.get());
#endif
        }
    }
#endif
}

bool Function::deserialize(ChunkSerializerOperations &op,
    ArchiveStreamReader &reader) {

    uint64_t address = reader.read<address_t>();
    setPosition(new AbsolutePosition(address));
    setName(reader.readString());

    bool compressedMode = reader.read<bool>();
    if(!compressedMode) {
        op.deserializeChildren(this, reader);
    }
    else {
        //op.deserializeChildren(this, reader);  // deserialize empty children!
        op.deserializeChildrenIDsOnly(this, reader, 2);

        PositionFactory *positionFactory = PositionFactory::getInstance();

        Chunk *prevChunk1 = this;

        size_t totalSize = 0;
        uint64_t blockCount = reader.read<uint32_t>();
        for(uint64_t b = 0; b < blockCount; b ++) {
            Block *block = getChildren()->getIterable()->get(b);
            block->setPosition(positionFactory->makePosition(
                prevChunk1, block, this->getSize()));

            if(b > 0) {
                block->setPreviousSibling(prevChunk1);
                prevChunk1->setNextSibling(block);
            }

            Chunk *prevChunk2 = block;

            uint64_t instrCount = reader.read<uint32_t>();
            for(uint64_t i = 0; i < instrCount; i ++) {
                auto instr = block->getChildren()->getIterable()->get(i);

                if(i > 0) {
                    instr->setPreviousSibling(prevChunk2);
                    prevChunk2->setNextSibling(instr);
                }

                auto semantic = InstrSerializer(op).deserialize(instr,
                    address + totalSize, reader);
                instr->setSemantic(semantic);

                instr->setPosition(positionFactory->makePosition(
                    prevChunk2, instr, block->getSize()));
                prevChunk2 = instr;

                totalSize += instr->getSize();
                block->addToSize(instr->getSize());
                //ChunkMutator(block, true);  // recalculate addresses
            }

            this->addToSize(block->getSize());
            prevChunk1 = block;
        }

        ChunkMutator(this, true);  // recalculate addresses
    }
    return reader.stillGood();
}

void Function::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}

void FunctionList::serialize(ChunkSerializerOperations &op,
    ArchiveStreamWriter &writer) {

    op.serializeChildren(this, writer);
}

bool FunctionList::deserialize(ChunkSerializerOperations &op,
    ArchiveStreamReader &reader) {

    op.deserializeChildren(this, reader);
    return reader.stillGood();
}

void FunctionList::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}
