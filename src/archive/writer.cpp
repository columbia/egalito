#include <cstring>  // for std::strlen
#include <fstream>
#include "generic.h"
#include "writer.h"
#include "stream.h"
#include "log/log.h"

void EgalitoArchiveWriter::writeTo(std::string filename) {
    assignOffsets();
    writeData(filename);
}

void EgalitoArchiveWriter::assignOffsets() {
    uint32_t totalSize = 0;
    totalSize += std::strlen(EgalitoArchive::signature);
    totalSize += sizeof(EgalitoArchive::version);
    totalSize += sizeof(uint32_t);  // chunk count

    for(auto &flat : flatList) {
        flat.setOffset(totalSize);
        totalSize += sizeof(uint16_t) + sizeof(uint32_t)*3 + flat.getSize();
    }
}

void EgalitoArchiveWriter::writeData(std::string filename) {
    std::ofstream file(filename, std::ios::out | std::ios::binary);

    // write the file header
    {
        ArchiveStreamWriter writer(file);
        writer.write(EgalitoArchive::signature);
        writer.write(EgalitoArchive::version);
        writer.write(static_cast<uint32_t>(flatList.getCount()));
    }

    for(const auto &flat : flatList) {
        LOG(9, "write FlatChunk id=" << flat.getID()
            << " type=" << flat.getType());
        ArchiveStreamWriter writer(file);
        writer.write(flat.getType());
        writer.write(flat.getID());
        writer.write(flat.getOffset());
        writer.write(flat.getSize());
        writer.write(flat.getData());
    }

    file.close();
}
