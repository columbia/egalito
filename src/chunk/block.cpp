#include "block.h"
#include "visitor.h"

void Block::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}
