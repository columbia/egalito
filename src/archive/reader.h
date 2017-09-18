#ifndef EGALITO_ARCHIVE_READER_H
#define EGALITO_ARCHIVE_READER_H

#include <iosfwd>
#include "flatchunk.h"

class EgalitoArchiveReader {
private:
    FlatChunkList flatList;
    uint32_t flatCount;
public:
    void readFlatList(std::string filename);

    FlatChunkList &getFlatList() { return flatList; }
private:
    bool readHeader(std::ifstream &file);
};

#endif
