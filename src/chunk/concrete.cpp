#include <sstream>
#include <iomanip>
#include "concrete.h"

std::string Module::getName() const {
    std::ostringstream stream;
    auto count = getChildren()->getIterable()->getCount();
    stream << "module-" << count << "-functions";
    return stream.str();
}

size_t PLTList::getPLTTrampolineSize() {
#ifdef ARCH_X86_64
    return 16;
#else
    return 16;
#endif
}

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
