#ifndef EGALITO_TRANSFORM_H
#define EGALITO_TRANSFORM_H

#include "generation.h"

class Transform {
public:
    template <typename B, typename A>
    Generation transform(const Generation &source, Sandbox<B, A> &sandbox);
};

#endif
