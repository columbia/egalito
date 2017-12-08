#ifndef EGALITO_ARCHIVE_READER_H
#define EGALITO_ARCHIVE_READER_H

#include <iosfwd>
#include "archive.h"

class LibraryList;

class EgalitoArchiveReader {
public:
    EgalitoArchive *read(std::string filename);
    EgalitoArchive *read(std::string filename, LibraryList *libraryList);
private:
    bool readHeader(std::ifstream &file, uint32_t &flatCount,
        uint32_t &version);
};

#endif
