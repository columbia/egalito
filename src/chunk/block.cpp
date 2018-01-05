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

    // not called for Functions, just for PLTTrampolines
    //writer.write(getAddress());
    writer.write(op.assign(getPreviousSibling() ? getPreviousSibling() : getParent()));

    op.serializeChildren(this, writer);
}

bool Block::deserialize(ChunkSerializerOperations &op,
    ArchiveStreamReader &reader) {

    // not called for Functions, just for PLTTrampolines
    //auto address = reader.read<address_t>();
    //setPosition(new AbsolutePosition(address));
    auto afterThis = op.lookup(reader.readID());
    setPosition(new SubsequentPosition(afterThis));

    op.deserializeChildren(this, reader);
    return reader.stillGood();
}

void Block::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}
