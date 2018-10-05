#include "types.h"

size_t BaseGen::shdrIndexOf(Section *section) {
    return sectionList.indexOf(section);
}

size_t BaseGen::shdrIndexOf(const std::string &name) {
    return sectionList.indexOf(name);
}
