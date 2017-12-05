#include <sstream>
#include <string>
#include <cstring>  // for std::strlen
#include "stream.h"
#include "flatchunk.h"

bool ArchiveStreamReader::readInto(uint8_t &value) {
    stream.read(reinterpret_cast<char *>(&value), sizeof(value));
    return stream.operator bool ();
}

bool ArchiveStreamReader::readInto(uint16_t &value) {
    stream.read(reinterpret_cast<char *>(&value), sizeof(value));
    return stream.operator bool ();
}

bool ArchiveStreamReader::readInto(uint32_t &value) {
    stream.read(reinterpret_cast<char *>(&value), sizeof(value));
    return stream.operator bool ();
}

bool ArchiveStreamReader::readInto(uint64_t &value) {
    stream.read(reinterpret_cast<char *>(&value), sizeof(value));
    return stream.operator bool ();
}

bool ArchiveStreamReader::readInto(bool &flag) { 
    uint8_t value;
    bool success = readInto(value);
    flag = (value == '1');
    return success;
}

std::string ArchiveStreamReader::readString() {
    std::string value;
    std::getline(stream, value, '\0');
    return std::move(value);
}

std::string ArchiveStreamReader::readFixedLengthBytes(size_t length) {
    std::string value;
    value.resize(length);
    stream.read(&value[0], length);
    return std::move(value);
}

bool ArchiveStreamReader::stillGood() {
    return stream.good();
}

void ArchiveStreamWriter::writeValue(uint8_t value) {
    stream.write(reinterpret_cast<const char *>(&value), sizeof(value));
}

void ArchiveStreamWriter::writeValue(uint16_t value) {
    stream.write(reinterpret_cast<const char *>(&value), sizeof(value));
}

void ArchiveStreamWriter::writeValue(uint32_t value) {
    stream.write(reinterpret_cast<const char *>(&value), sizeof(value));
}

void ArchiveStreamWriter::writeValue(uint64_t value) {
    stream.write(reinterpret_cast<const char *>(&value), sizeof(value));
}

void ArchiveStreamWriter::writeString(const char *value) {
    stream.write(value, std::strlen(value) + 1);
}

void ArchiveStreamWriter::writeString(const std::string &value) {
    stream.write(value.c_str(), value.length() + 1);
}

void ArchiveStreamWriter::writeFixedLengthBytes(const char *value,
    size_t length) {

    stream.write(value, length);
}

void ArchiveStreamWriter::writeFixedLengthBytes(const char *value) {
    stream.write(value, std::strlen(value));
}

BufferedStreamWriter::BufferedStreamWriter(FlatChunk *flat)
    : ArchiveStreamWriter(stream), flat(flat), stream(flat->getData()) {
}

BufferedStreamWriter::~BufferedStreamWriter() {
    std::string data = stream.str();
    if(data.length() > 0) {
        flat->appendData(stream.str());
    }
}

void BufferedStreamWriter::flush() {
    flat->appendData(stream.str());
    stream.str(std::string());
}

InMemoryStreamReader::InMemoryStreamReader(FlatChunk *flat)
    : ArchiveStreamReader(stream), stream(flat->getData()) {
}
