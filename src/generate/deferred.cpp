#include "deferred.h"

std::ostream &operator << (std::ostream &stream, DeferredValue &dv) {
    dv.writeTo(stream);
    return stream;
}

void DeferredValueCString::writeTo(std::ostream &stream) {
    stream.write(reinterpret_cast<const char *>(getPtr()), getSize());
}
