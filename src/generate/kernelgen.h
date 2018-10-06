#ifndef EGALITO_GENERATE_KERNELGEN_H
#define EGALITO_GENERATE_KERNELGEN_H

#include "basegen.h"

class KernelGen : public ElfGeneratorImpl {
public:
    KernelGen(Program *program, SandboxBacking *backing);

    virtual void preCodeGeneration();
    virtual void afterAddressAssign();
    virtual void generateContent(const std::string &filename);
};

#endif
