#include <sstream>
#include <iomanip>
#include "concrete.h"

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
