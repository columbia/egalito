#include "dataregion.h"
#include "link.h"
#include "visitor.h"

void DataRegion::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}

void DataRegionList::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}
