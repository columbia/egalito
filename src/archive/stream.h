#ifndef EGALITO_ARCHIVE_STREAM_H
#define EGALITO_ARCHIVE_STREAM_H

#include <iosfwd>
#include <sstream>
#include <cstdint>

class FlatChunk;

class ArchiveStreamReader {
private:
    std::istream &stream;
public:
    ArchiveStreamReader(std::istream &stream) : stream(stream) {}
    virtual ~ArchiveStreamReader() {}

    bool read(uint16_t &value);
    bool read(uint32_t &value);
    bool read(uint64_t &value);
    bool read(std::string &value, size_t length);
    bool readAnyLength(std::string &value);

    bool stillGood();
};

class ArchiveStreamWriter {
private:
    std::ostream &stream;
public:
    ArchiveStreamWriter(std::ostream &stream) : stream(stream) {}
    virtual ~ArchiveStreamWriter() {}

    void write(uint16_t value);
    void write(uint32_t value);
    void write(uint64_t value);
    void write(const char *value);
    void write(const std::string &value);
    void writeAnyLength(const char *value);
    void writeAnyLength(const std::string &value);

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
