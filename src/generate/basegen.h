#ifndef EGALITO_GENERATE_BASEGEN_H
#define EGALITO_GENERATE_BASEGEN_H

#include <string>
#include "data.h"

class ElfGeneratorBase {
public:
    virtual ~ElfGeneratorBase() {}

    /** Run before any generate-specific code. */
    virtual void preCodeGeneration() = 0;

    /** Run after addresses are assigned to functions, but before their
        code is generated. Function sizes are fixed at this point.
    */
    virtual void afterAddressAssign() = 0;

    /** Run after functions and data have been copied into memory.
    */
    virtual void generateContent(const std::string &filename) = 0;
};

class ElfGeneratorImpl : public ElfGeneratorBase {
private:
    ElfData *data;
    ElfConfig config;
public:
    ElfGeneratorImpl(Program *program, SandboxBacking *backing);

    ElfData *getData() { return data; }
    ElfConfig *getConfig() { return &config; }
};

#endif
