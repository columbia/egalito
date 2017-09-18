#include <cstring>  // for std::strlen
#include <fstream>
#include "generic.h"
#include "writer.h"
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

// !!! on aarch64, the endianness may need to change here

static void writeValue(std::ostream &stream, uint16_t value) {
    stream.write(reinterpret_cast<const char *>(&value), sizeof(value));
}
static void writeValue(std::ostream &stream, uint32_t value) {
    stream.write(reinterpret_cast<const char *>(&value), sizeof(value));
}
static void writeValue(std::ostream &stream, const char *value) {
    stream.write(value, std::strlen(value));
}
static void writeValue(std::ostream &stream, const std::string &value) {
    stream.write(value.c_str(), value.length());
}

void EgalitoArchiveWriter::writeData(std::string filename) {
    std::ofstream file(filename, std::ios::out | std::ios::binary);

    writeValue(file, EgalitoArchive::signature);
    writeValue(file, EgalitoArchive::version);
    writeValue(file, static_cast<uint32_t>(flatList.getCount()));

    for(const auto &flat : flatList) {
        LOG(9, "write FlatChunk id=" << flat.getID()
            << " type=" << flat.getType());
        writeValue(file, flat.getType());
        writeValue(file, flat.getID());
        writeValue(file, flat.getOffset());
        writeValue(file, flat.getSize());
        writeValue(file, flat.getData());
    }

    file.close();
}
