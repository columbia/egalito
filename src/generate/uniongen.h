#ifndef EGALITO_GENERATE_UNIONGEN_H
#define EGALITO_GENERATE_UNIONGEN_H

#include "basegen.h"

class UnionGen : public ElfGeneratorImpl {
public:
    virtual void preCodeGeneration();
    virtual void afterAddressAssign();
    virtual void generateContent(const std::string &filename);
};

#endif
