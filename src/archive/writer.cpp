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
        if(!flat) {
            LOG(1, "ERROR: null FlatChunk in list! Will crash soon.");
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
        writer.writeFixedLengthBytes(EgalitoArchive::SIGNATURE);
        writer.write<uint32_t>(EgalitoArchive::VERSION);
        writer.write<uint32_t>(archive->getFlatList().getCount());
    }

    for(auto flat : archive->getFlatList()) {
        LOG(10, "write FlatChunk id=" << flat->getID() << " type=" << flat->getType());
        ArchiveStreamWriter writer(file);
        writer.write<uint16_t>(flat->getType());
        writer.write<uint32_t>(flat->getID());
        writer.write<uint32_t>(flat->getOffset());
        writer.write<uint32_t>(flat->getSize());
        writer.writeFixedLengthBytes(flat->getData().c_str(), flat->getSize());
    }

    file.close();
}
