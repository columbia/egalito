#ifndef EGALITO_TRANSFORM_H
#define EGALITO_TRANSFORM_H

#include "chunk/generation.h"

class Transform {
public:
    Generation transform(const Generation &source, Sandbox *sandbox);
};

#endif
