#include <cassert>
#include "position.h"
#include "chunk.h"

address_t RelativePosition::get() const {
    //assert(relativeTo != nullptr);
    if(!relativeTo) return offset.get();
    return relativeTo->getAddress() + offset.get();
}

void RelativePosition::set(address_t value) {
    assert(relativeTo != nullptr);

    setOffset(value - relativeTo->getAddress());
}

void RelativePosition::finalize() {
    assert(relativeTo != nullptr);

    if(!relativeTo->contains(offset.get())) {
        throw "RelativePosition is outside bounds of enclosing Chunk";
    }

    offset.finalize();
}

size_t CalculatedSize::get() const {
    if(!valid) throw "Can't get invalidated summation size!";

    return cache;
}

#if 0
void Position::resolve(Chunk *relativeTo, bool makeRelative) {
    this->relativeTo = relativeTo;

    if(makeRelative) {
        auto within = relativeTo->getPosition();
        //...
    }
}
#endif
