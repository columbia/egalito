#include "integerdeferred.h"

void DeferredIntegerList::add(uint32_t value) {
    std::string str{reinterpret_cast<char *>(&value), sizeof(value)};
    stream << str;
}

void DeferredIntegerList::add(uint64_t value) {
    std::string str{reinterpret_cast<char *>(&value), sizeof(value)};
    stream << str;
}

size_t DeferredIntegerList::getSize() const {
    auto data = this->stream.str();
    return data.length();
}

void DeferredIntegerList::writeTo(std::ostream &stream) {
    auto data = this->stream.str();
    stream << data;
}
