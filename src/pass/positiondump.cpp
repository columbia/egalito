#include "positiondump.h"
#include "log/log.h"

void PositionDump::visit(Chunk *chunk, int indent) {
    for(int i = 0; i < indent; i ++) LOG0(1, "    ");

    LOG0(1, chunk->getName() << " has ");
    auto pos = chunk->getPosition();
    if(auto v = dynamic_cast<AbsolutePosition *>(pos)) {
        LOG(1, "AbsolutePosition " << pos->get());
    }
    else if(auto v = dynamic_cast<OffsetPosition *>(pos)) {
        LOG(1, "OffsetPosition at "
            << v->getDependency()->getName()
            << " + " << v->getOffset());
    }
    else if(auto v = dynamic_cast<SubsequentPosition *>(pos)) {
        LOG(1, "SubsequentPosition after "
            << v->getDependency()->getName() << ", i.e. after "
            << v->getDependency()->getPosition()->get());
    }
    else {
        LOG(1, "???");
    }

    if(chunk->getChildren()) {
        for(auto child : chunk->getChildren()->genericIterable()) {
            visit(child, indent + 1);
        }
    }
}
