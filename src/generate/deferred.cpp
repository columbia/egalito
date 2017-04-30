#include "deferred.h"

std::ostream &operator << (std::ostream &stream, DeferredValue &dv) {
    dv.writeTo(stream);
    return stream;
}

void DeferredValueCString::writeTo(std::ostream &stream) {
    stream.write(reinterpret_cast<const char *>(getPtr()), getSize());
}

size_t DeferredStringList::add(const std::string &data, bool withNull) {
    size_t len = data.length();
    if(withNull) len ++;
    output.append(data.c_str(), len);
}

size_t DeferredStringList::add(const char *str, bool withNull) {
    size_t len = strlen(str);
    if(withNull) len ++;
    output.append(str, len);
}

void DeferredString::writeTo(std::ostream &stream) {
    stream.write(value.c_str(), value.length());
}

void DeferredStringList::writeTo(std::ostream &stream) {
    stream.write(output.c_str(), output.length());
}
