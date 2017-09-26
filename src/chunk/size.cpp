#include <cassert>
#include "size.h"

void ComputedSize::adjustBy(diff_t add) {
    assert(static_cast<diff_t>(size + add) >= 0);
    size += add;
}
