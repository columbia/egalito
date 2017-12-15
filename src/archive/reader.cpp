#include <fstream>
#include <cstring>  // for std::strlen
#include "reader.h"
#include "archive.h"
#include "flatchunk.h"
#include "stream.h"
#include "chunk/chunk.h"
#include "chunk/library.h"
#include "log/log.h"

bool EgalitoArchiveReader::readHeader(std::ifstream &file,
    uint32_t &flatCount, uint32_t &version) {

    ArchiveStreamReader reader(file);
    std::string line = reader.readFixedLengthBytes(
        std::strlen(EgalitoArchive::SIGNATURE));
    if(!reader.stillGood() || line != EgalitoArchive::SIGNATURE) {
        LOG(0, "Error: file signature does not match, not an Egalito archive");
        return false;
    }

    if(!reader.readInto(version)) {
        LOG(0, "Error: archive does not contain a version");
        return false;
    }
    if(version > EgalitoArchive::VERSION) {
        LOG(0, "Error: file version " << version
            << " is newer than supported version " << EgalitoArchive::VERSION);
        return false;
    }
    if(version < EgalitoArchive::VERSION) {
        LOG(0, "Warning: file version " << version
            << " is old, trying to load it anyway");
        // fall-through
    }

    if(!reader.readInto(flatCount) || flatCount == 0) {
        LOG(0, "Warning: empty Egalito archive");
        // fall-through
    }

    return true;  // Success
}

EgalitoArchive *EgalitoArchiveReader::read(std::string filename) {
    std::ifstream file(filename, std::ios::in | std::ios::binary);

    uint32_t flatCount, version;
    if(!readHeader(file, flatCount, version)) return nullptr;

    EgalitoArchive *archive = new EgalitoArchive(filename, version);

    for(uint32_t i = 0; i < flatCount; i ++) {
        ArchiveStreamReader reader(file);
        auto type   = decodeChunkType(reader.read<uint8_t>());
        auto id     = reader.read<uint32_t>();
        auto offset = reader.read<uint32_t>();
        auto size   = reader.read<uint32_t>();
        std::string data = reader.readFixedLengthBytes(size);

        if(!file) {
            LOG(0, "Error: unexpected EOF in archive");
            delete archive;
            return nullptr;
        }
        LOG(10, "read FlatChunk id=" << id << " type=" << type);

        FlatChunk *flat = new FlatChunk(type, id, data);
        flat->setOffset(offset);
        archive->getFlatList().addFlatChunk(flat);
    }

    file.close();
    return archive;
}

EgalitoArchive *EgalitoArchiveReader::read(std::string filename,
    LibraryList *libraryList) {

    for(auto path : libraryList->getSearchPaths()) {
        auto archive = read(path + "/" + filename);
        if(archive) return archive;
    }

    return read(filename);  // try the unadorned filename last
}
