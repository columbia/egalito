#ifndef EGALITO_ARCHIVE_STREAM_H
#define EGALITO_ARCHIVE_STREAM_H

#include <iosfwd>
#include <cstdint>

class ArchiveStreamReader {
private:
    std::istream &stream;
public:
    ArchiveStreamReader(std::istream &stream) : stream(stream) {}

    bool read(uint16_t &value);
    bool read(uint32_t &value);
    bool read(std::string &value, size_t length);
    bool readAnyLength(std::string &value);
};

class ArchiveStreamWriter {
private:
    std::ostream &stream;
public:
    ArchiveStreamWriter(std::ostream &stream) : stream(stream) {}

    void write(uint16_t value);
    void write(uint32_t value);
    void write(const char *value);
    void write(const std::string &value);
    void writeAnyLength(const char *value);
    void writeAnyLength(const std::string &value);
};

#endif
