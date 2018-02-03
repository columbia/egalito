#include <sstream>
#include "block.h"
#include "serializer.h"
#include "instr/serializer.h"
#include "visitor.h"
#include "dump.h"
#include "disasm/disassemble.h"  // for debugging!
#include "concrete.h"  // for ChunkIter
#include "operation/mutator.h"
#include "log/log.h"

std::string Block::getName() const {
    std::ostringstream stream;
    if(getParent()) {
        if(getParent()->getName() != "???") {
            stream << getParent()->getName() << "/";
        }

        stream << "bb+" << (getAddress() - getParent()->getAddress());
    }
    else stream << "bb-anonymous";
    return stream.str();
}

void Block::serialize(ChunkSerializerOperations &op,
    ArchiveStreamWriter &writer) {

    // not called for Functions, just for PLTTrampolines
#if 0
    writer.write(getAddress());
    writer.write(op.assign(getPreviousSibling() ? getPreviousSibling() : getParent()));
    writer.write<size_t>(getAddress() - getParent()->getAddress());
    writer.write<size_t>(getSize());


    {
        op.serializeChildrenIDsOnly(this, writer, 1);
        writer.write<uint32_t>(getChildren()->getIterable()->getCount());
        for(auto instr : CIter::children(this)) {
#if 1
            InstrSerializer(op).serialize(instr->getSemantic(), writer);
#else
            InstrWriterGetData instrWriter;
            instr->getSemantic()->accept(&instrWriter);
            writer.writeAnyLength(instrWriter.get());
#endif
        }
    }

    //op.serializeChildren(this, writer);
#else
    writer.write(getAddress());
    writer.write(op.assign(getPreviousSibling() ? getPreviousSibling() : getParent()));
    writer.write<size_t>(getAddress() - getParent()->getAddress());
    writer.write<size_t>(getSize());

    /*LOG(1, "serialize Block at offset " << (getAddress() - getParent()->getAddress())
        << " of size " << getSize());*/

    op.serializeChildren(this, writer);
#endif
}

bool Block::deserialize(ChunkSerializerOperations &op,
    ArchiveStreamReader &reader) {

    // not called for Functions, just for PLTTrampolines
#if 0
    auto address = reader.read<address_t>();
    //setPosition(new AbsolutePosition(address));
    auto afterThis = op.lookup(reader.readID());
    auto offset = reader.read<size_t>();
    setPosition(PositionFactory::getInstance()->makePosition(afterThis, this,
        offset));
    //size_t size = reader.read<size_t>();

    {
        op.deserializeChildrenIDsOnly(this, reader, 1);
        PositionFactory *positionFactory = PositionFactory::getInstance();
        size_t totalSize = 0;
        Chunk *prevChunk2 = this;

        uint64_t instrCount = reader.read<uint32_t>();
        for(uint64_t i = 0; i < instrCount; i ++) {
            auto instr = this->getChildren()->getIterable()->get(i);

            if(i > 0) {
                instr->setPreviousSibling(prevChunk2);
                prevChunk2->setNextSibling(instr);
            }

            auto semantic = InstrSerializer(op).deserialize(instr,
                address + totalSize, reader);
            instr->setSemantic(semantic);

            instr->setPosition(positionFactory->makePosition(
                prevChunk2, instr, this->getSize()));
            prevChunk2 = instr;

            totalSize += instr->getSize();
            this->addToSize(instr->getSize());
        }
    }
    ChunkMutator{this, true};  // recalculate addresses

    //op.deserializeChildren(this, reader);
    //setSize(size);
#elif 0
    auto address = reader.read<address_t>();
    //setPosition(new AbsolutePosition(address));
    auto afterThis = op.lookup(reader.readID());
    auto offset = reader.read<size_t>();
    setPosition(PositionFactory::getInstance()->makePosition(afterThis, this,
        offset));
    size_t size = reader.read<size_t>();

    LOG(1, "deserialized Block at offset " << offset << " of size " << size);

    op.deserializeChildren(this, reader);
    for(size_t i = 0; i < getChildren()->getIterable()->getCount(); i ++) {
        auto child = getChildren()->getIterable()->get(i);
        child->setPosition(new OffsetPosition(child, 100+i));
    }
    /*if(getChildren()->getIterable()->getCount() > 0) {
        getChildren()->getIterable()->get(0)->setPosition(new OffsetPosition(this, 0));
    }*/
    ChunkMutator{this};

    //LOG(1, "size should be " << size << " and it's " << this->getSize());
    setSize(size);
#else
    auto address = reader.read<address_t>();
    //setPosition(new AbsolutePosition(address));
    auto afterThis = op.lookup(reader.readID());
    auto offset = reader.read<size_t>();
    setPosition(PositionFactory::getInstance()->makePosition(afterThis, this,
        offset));
    size_t size = reader.read<size_t>();

    //LOG(1, "deserialized Block at offset " << offset << " of size " << size);

    op.deserializeChildren(this, reader);
    {
        PositionFactory *positionFactory = PositionFactory::getInstance();
        Chunk *prevChunk = this;

        for(uint64_t i = 0; i < getChildren()->genericGetSize(); i ++) {
            auto instr = this->getChildren()->getIterable()->get(i);

            if(i > 0) {
                instr->setPreviousSibling(prevChunk);
                prevChunk->setNextSibling(instr);
            }

            instr->setPosition(positionFactory->makePosition(
                prevChunk, instr, this->getSize()));
            prevChunk = instr;

            this->addToSize(instr->getSize());
        }
    }
    ChunkMutator{this, true};  // recalculate addresses

    //LOG(1, "size should be " << size << " and it's " << this->getSize());
    setSize(size);
#endif
    return reader.stillGood();
}

void Block::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}
