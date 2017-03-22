#ifndef EGALITO_PASS_CAPSTONESIZE_H
#define EGALITO_PASS_CAPSTONESIZE_H

#include "chunkpass.h"

/** Calculate the size of memory used by Capstone data structures */
class CapstoneSizePass : public ChunkPass {
private:
    size_t count;
    size_t cs_size;
    size_t raw_size;

public:
    CapstoneSizePass() : count(0), cs_size(0), raw_size(0) {}
    virtual void visit(Instruction *instruction);
    size_t getCount() const { return count; }
    size_t getSize() const { return cs_size; }
    size_t getRawSize() const { return raw_size; }

private:
    void accumulate(size_t size);
};

#endif
