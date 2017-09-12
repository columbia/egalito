#ifndef EGALITO_ARCHIVE_WRITER_H
#define EGALITO_ARCHIVE_WRITER_H

#include "flatchunk.h"

class EgalitoArchiveReader {
private:
    FlatChunkList flatList;
public:
    void readData(std::string filename);
};

#endif
