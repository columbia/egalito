#ifndef EGALITO_CHUNK_SIZE_H
#define EGALITO_CHUNK_SIZE_H

#include "types.h"
#include "util/range.h"

class ComputedSize {
private:
    size_t size;
public:
    ComputedSize() : size(0) {}
    size_t get() const { return size; }
    void set(size_t newSize) { size = newSize; }
    void adjustBy(diff_t add);
};

#endif
