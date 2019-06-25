#ifndef EGALITO_PE_PEMAP_H
#define EGALITO_PE_PEMAP_H

#ifdef USE_WIN64_PE

#include <vector>
#include <string>
#include "types.h"
#include "exefile/exemap.h"

#include "parser-library/parse.h"

class PESection : public ExeSectionImpl {
private:
    peparse::bounded_buffer *buffer;
public:
    PESection(int index, const std::string &name, address_t baseAddress,
        peparse::image_section_header header, peparse::bounded_buffer *buffer);

    peparse::bounded_buffer *getBuffer() const { return buffer; }
    virtual size_t getSize() const { return buffer->bufLen; }

    virtual bool isExecutable() const { return true; }
};

class PEMap : public ExeMapImpl<PESection> {
private:
    peparse::parsed_pe *peRef;
public:
    PEMap(const std::string &filename);
    ~PEMap();

    virtual PEMap *asPE() { return this; }

    static bool isPE(const std::string &filename);
private:
    void throwError(const std::string &err);
    void setup();
    void parsePE(const std::string &filename);
    void verifyPE();
    void makeSectionMap();
    //void makeSegmentList();
    //void makeVirtualAddresses();
public:
    virtual address_t getEntryPoint() const;
};

#else

class PEMap : public ExeMap {
};

#endif  // USE_WIN64_PE
#endif
