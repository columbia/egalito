#ifndef EGALITO_ARCHIVE_WRITER_H
#define EGALITO_ARCHIVE_WRITER_H

#include <string>
#include "archive.h"

class EgalitoArchiveWriter {
private:
    EgalitoArchive *archive;
public:
    EgalitoArchiveWriter(EgalitoArchive *archive) : archive(archive) {}
    void write(std::string filename);
private:
    void assignOffsets();
    void writeData(std::string filename);
};

#endif
