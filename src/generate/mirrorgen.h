#ifndef EGALITO_GENERATE_MIRRORGEN_H
#define EGALITO_GENERATE_MIRRORGEN_H

#include "basegen.h"

class MakeGlobalPLT;
class MirrorGen : public ElfGeneratorImpl {
public:
    MirrorGen(Program *program, SandboxBacking *backing);

    virtual void preCodeGeneration();
    virtual void afterAddressAssign();
    virtual void generateContent(const std::string &filename);
};

#endif
