#ifndef EGALITO_ARCHIVE_WRITER_H
#define EGALITO_ARCHIVE_WRITER_H

#include "flatchunk.h"

class EgalitoArchiveWriter {
private:
    FlatChunkList flatList;
public:
    void writeTo(std::string filename);

    FlatChunkList &getFlatList() { return flatList; }
private:
    void assignOffsets();
    void writeData(std::string filename);
};

#endif
