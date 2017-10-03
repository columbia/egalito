#include <sstream>
#include "block.h"
#include "serializer.h"
#include "visitor.h"
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

    LOG(1, "serialize block " << getName());

    //writer.write(static_cast<uint64_t>(getAddress()));
    //op.serializeChildren(this, writer);
}

bool Block::deserialize(ChunkSerializerOperations &op,
    ArchiveStreamReader &reader) {

    uint64_t address = 0;
    //reader.read(address);
    setPosition(new AbsolutePosition(address));

    //op.deserializeChildren(this, reader);
    return reader.stillGood();
}

void Block::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}
