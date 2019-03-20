#ifndef EGALITO_GENERATE_INTEGER_DEFERRED_H
#define EGALITO_GENERATE_INTEGER_DEFERRED_H

#include <sstream>
#include "deferred.h"

class DeferredIntegerList : public DeferredValue {
private:
    std::ostringstream stream;
public:
    void add(uint32_t value);
    void add(uint64_t value);
    virtual size_t getSize() const;
    virtual void writeTo(std::ostream &stream);
};

#endif
