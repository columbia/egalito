#include "program.h"
#include "visitor.h"

void Program::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}
