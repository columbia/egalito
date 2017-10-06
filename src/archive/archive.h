#ifndef EGALITO_ARCHIVE_ARCHIVE_H
#define EGALITO_ARCHIVE_ARCHIVE_H

#include <cstdint>
#include "flatchunk.h"
#include "chunktypes.h"

class EgalitoArchive {
public:
    static const char *SIGNATURE;
    static const uint32_t VERSION = 3;
private:
    FlatChunkList flatList;
    std::string sourceFilename;
public:
    EgalitoArchive() : sourceFilename("(in-memory)") {}
    EgalitoArchive(std::string filename) : sourceFilename(filename) {}

    FlatChunkList &getFlatList() { return flatList; }
};

#endif
