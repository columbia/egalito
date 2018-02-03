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
    //writer.write(getAddress());
    writer.write(op.assign(getPreviousSibling() ? getPreviousSibling() : getParent()));
    writer.write<size_t>(getAddress() - getParent()->getAddress());
    writer.write<size_t>(getSize());

    /*LOG(1, "serialize Block at offset " << (getAddress() - getParent()->getAddress())
        << " of size " << getSize());*/

    op.serializeChildren(this, writer);
}

bool Block::deserialize(ChunkSerializerOperations &op,
    ArchiveStreamReader &reader) {

    // not called for Functions, just for PLTTrampolines
    //auto address = reader.read<address_t>();
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

    setSize(size);
    return reader.stillGood();
}

void Block::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}
