#include <string>
#include <sstream>
#include "module.h"
#include "visitor.h"

std::string Module::getName() const {
    std::ostringstream stream;
    auto count = getChildren()->getIterable()->getCount();
    stream << "module-" << count << "-functions";
    return stream.str();
}

void Module::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}
