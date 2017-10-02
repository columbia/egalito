#include <sstream>
#include "block.h"
#include "visitor.h"

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

void Block::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}
