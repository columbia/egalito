#include <string>
#include <sstream>
#include "module.h"
#include "elf/elfspace.h"
#include "elf/sharedlib.h"
#include "visitor.h"

std::string Module::getName() const {
    std::ostringstream stream;
    auto lib = elfSpace->getLibrary();
    if(lib) {
        stream << "module-" << lib->getShortName();
    }
    else {
        stream << "module-main";
    }
    return stream.str();
}

void Module::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}
