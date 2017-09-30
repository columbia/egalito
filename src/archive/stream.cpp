#include <sstream>
#include <cstring>  // for std::strlen
#include "stream.h"
#include "flatchunk.h"
#include "log/log.h"

// !!! on aarch64, the endianness may need to change here
bool ArchiveStreamReader::read(uint16_t &value) {
    stream.read(reinterpret_cast<char *>(&value), sizeof(value));
    return stream.operator bool ();
}

bool ArchiveStreamReader::read(uint32_t &value) {
    stream.read(reinterpret_cast<char *>(&value), sizeof(value));
    return stream.operator bool ();
}

bool ArchiveStreamReader::read(uint64_t &value) {
    stream.read(reinterpret_cast<char *>(&value), sizeof(value));
    return stream.operator bool ();
}

bool ArchiveStreamReader::read(std::string &value, size_t length) {
    value.resize(length);
    stream.read(&value[0], length);
    return stream.operator bool ();
}

bool ArchiveStreamReader::readAnyLength(std::string &value) {
    uint32_t length;
    return this->read(length) && this->read(value, length);
}

bool ArchiveStreamReader::stillGood() {
    return stream.good();
}

void ArchiveStreamWriter::write(uint16_t value) {
    stream.write(reinterpret_cast<const char *>(&value), sizeof(value));
}

void ArchiveStreamWriter::write(uint32_t value) {
    stream.write(reinterpret_cast<const char *>(&value), sizeof(value));
}

void ArchiveStreamWriter::write(uint64_t value) {
    stream.write(reinterpret_cast<const char *>(&value), sizeof(value));
}

void ArchiveStreamWriter::write(const char *value) {
    stream.write(value, std::strlen(value));
}

void ArchiveStreamWriter::write(const std::string &value) {
    stream.write(value.c_str(), value.length());
}

void ArchiveStreamWriter::writeAnyLength(const char *value) {
    this->write(static_cast<uint32_t>(std::strlen(value)));
    this->write(value);
}

void ArchiveStreamWriter::writeAnyLength(const std::string &value) {
    this->write(static_cast<uint32_t>(value.length()));
    this->write(value);
}

BufferedStreamWriter::BufferedStreamWriter(FlatChunk *flat)
    : ArchiveStreamWriter(stream), flat(flat), stream(flat->getData()) {
}

BufferedStreamWriter::~BufferedStreamWriter() {
    LOG(1, "buffered up data [" << stream.str() << "]");
    flat->appendData(stream.str());
}
