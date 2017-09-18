#include <fstream>
#include <cstring>  // for std::strlen
#include "reader.h"
#include "generic.h"
#include "flatchunk.h"
#include "chunk/chunk.h"
#include "log/log.h"

static void readValue(std::istream &stream, uint16_t &value) {
    stream.read(reinterpret_cast<char *>(&value), sizeof(value));
}
static void readValue(std::istream &stream, uint32_t &value) {
    stream.read(reinterpret_cast<char *>(&value), sizeof(value));
}
static void readValue(std::istream &stream, std::string &value, size_t length) {
    value.resize(length);
    stream.read(&value[0], length);
}

bool EgalitoArchiveReader::readHeader(std::ifstream &file) {
    std::string line;
    readValue(file, line, std::strlen(EgalitoArchive::signature));
    if(!file || line != EgalitoArchive::signature) {
        LOG(0, "Error: file signature does not match, not an Egalito archive");
        return false;
    }

    uint32_t version;
    readValue(file, version);
    if(!file) {
        LOG(0, "Error: archive does not contain a version");
        return false;
    }
    if(version > EgalitoArchive::version) {
        LOG(0, "Error: file version " << version
            << " is newer than supported version " << EgalitoArchive::version);
        return false;
    }
    if(version < EgalitoArchive::version) {
        LOG(0, "Warning: file version " << version
            << " is old, but proceeding to load as usual");
        // fall-through
    }

    readValue(file, flatCount);
    if(!file || flatCount == 0) {
        LOG(0, "Warning: empty Egalito archive");
        // fall-through
    }

    return true;  // Success
}

void EgalitoArchiveReader::readFlatList(std::string filename) {
    std::ifstream file(filename, std::ios::in | std::ios::binary);
    
    if(!readHeader(file)) return;

    for(uint32_t i = 0; i < flatCount; i ++) {
        uint16_t type;
        uint32_t id;
        uint32_t offset;
        uint32_t size;
        std::string data;
        readValue(file, type);
        readValue(file, id);
        readValue(file, offset);
        readValue(file, size);
        readValue(file, data, size);

        if(!file) {
            LOG(0, "Error: unexpected EOF in archive");
            return;
        }
        LOG(9, "read FlatChunk id=" << id << " type=" << type);

        FlatChunk flat(type, id, offset, data);
        flatList.newFlatChunk(flat);
    }

    file.close();
}
