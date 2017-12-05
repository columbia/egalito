#ifndef EGALITO_ARCHIVE_STREAM_H
#define EGALITO_ARCHIVE_STREAM_H

#include <iosfwd>
#include <sstream>
#include <cstdint>

#include "flatchunk.h"  // for FlatChunk::IDType

class ArchiveStreamReader {
private:
    std::istream &stream;
public:
    ArchiveStreamReader(std::istream &stream) : stream(stream) {}
    virtual ~ArchiveStreamReader() {}

    bool readInto(uint8_t &value);
    bool readInto(uint16_t &value);
    bool readInto(uint32_t &value);
    bool readInto(uint64_t &value);
    // address_t, size_t also supported
    bool readInto(bool &flag);

    template <typename ValueType>
    ValueType read() {
        ValueType value = 0;
        readInto(value);  // ignore return value, can check stillGood() later
        return value;
    }
    FlatChunk::IDType readID() { return read<FlatChunk::IDType>(); }

    std::string readString();  // cannot contain NULLs
    template <typename SizeType = uint32_t>
    std::string readBytes() { return readFixedLengthBytes(read<SizeType>()); }
    std::string readFixedLengthBytes(size_t length);

    bool stillGood();
};

class ArchiveStreamWriter {
private:
    std::ostream &stream;
public:
    ArchiveStreamWriter(std::ostream &stream) : stream(stream) {}
    virtual ~ArchiveStreamWriter() {}

    void writeValue(uint8_t value);
    void writeValue(uint16_t value);
    void writeValue(uint32_t value);
    void writeValue(uint64_t value);
    // address_t, size_t also supported
    void writeValue(bool flag)
        { writeValue(static_cast<uint8_t>(flag ? '1' : '0')); }

    template <typename ValueType>
    void write(ValueType value) { writeValue(value); }
    void writeID(FlatChunk::IDType id) { writeValue(id); }

    void writeString(const char *value);
    void writeString(const std::string &value);
    template <typename SizeType = uint32_t>
    void writeBytes(const std::string &value) {
        write<SizeType>(value.length());
        writeFixedLengthBytes(value.c_str(), value.length());
    }
    void writeFixedLengthBytes(const char *value, size_t length);
    void writeFixedLengthBytes(const char *value);  // runs strlen

    virtual void flush() {}
};

class FlatChunk;
class BufferedStreamWriter : public ArchiveStreamWriter {
private:
    FlatChunk *flat;
    std::ostringstream stream;
public:
    BufferedStreamWriter(FlatChunk *flat);
    ~BufferedStreamWriter();

    void flush();
};

class InMemoryStreamReader : public ArchiveStreamReader {
private:
    std::istringstream stream;
public:
    InMemoryStreamReader(FlatChunk *flat);
};

#endif
