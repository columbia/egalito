#ifndef EGALITO_ARCHIVE_READER_H
#define EGALITO_ARCHIVE_READER_H

#include <iosfwd>
#include "archive.h"

class ExternalData;

class EgalitoArchiveReader {
public:
    EgalitoArchive *read(std::string filename);
    EgalitoArchive *read(std::string filename, ExternalData *externalData);
private:
    bool readHeader(std::ifstream &file, uint32_t &flatCount,
        uint32_t &version);
};

#endif
