#include <cstring>  // for std::strlen
#include <fstream>
#include "writer.h"
#include "stream.h"
#include "log/log.h"

void EgalitoArchiveWriter::write(std::string filename) {
    assignOffsets();
    writeData(filename);
}

void EgalitoArchiveWriter::assignOffsets() {
    uint32_t totalSize = 0;
    totalSize += std::strlen(EgalitoArchive::SIGNATURE);
    totalSize += sizeof(EgalitoArchive::VERSION);
    totalSize += sizeof(uint32_t);  // chunk count

    for(auto flat : archive->getFlatList()) {
        LOG(1, "assign offsets for flat " << flat);
        if(!flat) {
            LOG(1, "ERROR: null FlatChunk in list!");
            continue;
        }
        flat->setOffset(totalSize);
        totalSize += sizeof(uint16_t) + sizeof(uint32_t)*3 + flat->getSize();
    }
}

void EgalitoArchiveWriter::writeData(std::string filename) {
    std::ofstream file(filename, std::ios::out | std::ios::binary);

    // write the file header
    {
        ArchiveStreamWriter writer(file);
        writer.write(EgalitoArchive::SIGNATURE);
        writer.write(EgalitoArchive::VERSION);
        writer.write(static_cast<uint32_t>(archive->getFlatList().getCount()));
    }

    for(auto flat : archive->getFlatList()) {
        if(!flat) continue;
        LOG(9, "write FlatChunk id=" << flat->getID()
            << " type=" << flat->getType());
        ArchiveStreamWriter writer(file);
        writer.write(flat->getType());
        writer.write(flat->getID());
        writer.write(flat->getOffset());
        writer.write(flat->getSize());
        writer.write(flat->getData());
    }

    file.close();
}
