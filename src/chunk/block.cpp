#include <sstream>
#include "block.h"
#include "serializer.h"
#include "visitor.h"
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

#if 0
    writer.write(static_cast<uint64_t>(getAddress()));
#endif
    op.serializeChildren(this, writer);
}

bool Block::deserialize(ChunkSerializerOperations &op,
    ArchiveStreamReader &reader) {

    op.deserializeChildren(this, reader);
#if 0
    uint64_t address = 0;
    reader.read(address);
    setPosition(new AbsolutePosition(address));

    op.deserializeChildren(this, reader);
#if 1
    PositionFactory *positionFactory = PositionFactory::getInstance();
    ChunkMutator mutator(this);
    Chunk *prevChunk = this;
    auto iterable = getChildren()->getIterable();
    for(size_t i = 0; i < iterable->getCount(); i ++) {
        Chunk *instr = iterable->get(i);
        mutator.setPreviousSibling(instr, prevChunk);
        if(i + 1 < iterable->getCount()) {
            mutator.setNextSibling(instr, iterable->get(i + 1));
        }
        instr->setPosition(
            positionFactory->makePosition(prevChunk, instr, this->getSize()));
        prevChunk = instr;
        //LOG(1, "set position of " << instr->getName() << " size " << instr->getSize());
    }

    mutator.updatePositions();
#endif
#endif
    return reader.stillGood();
}

void Block::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}
