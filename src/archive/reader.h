#ifndef EGALITO_ARCHIVE_READER_H
#define EGALITO_ARCHIVE_READER_H

#include <iosfwd>
#include "archive.h"

class EgalitoArchiveReader {
public:
    EgalitoArchive *read(std::string filename);
private:
    bool readHeader(std::ifstream &file, uint32_t &flatCount);
};

#endif
