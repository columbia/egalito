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
    int version;
public:
    EgalitoArchive() : sourceFilename("(in-memory)"), version(VERSION) {}
    EgalitoArchive(std::string filename, int version)
        : sourceFilename(filename), version(version) {}

    FlatChunkList &getFlatList() { return flatList; }

    int getVersion() const { return version; }
};

#endif
