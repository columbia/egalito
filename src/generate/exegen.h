#ifndef EGALITO_ELF_EXEGEN_H
#define EGALITO_ELF_EXEGEN_H

#include <iosfwd>
#include <vector>
#include <utility>
#include <elf.h>
#include "transform/sandbox.h"
#include "util/iter.h"
#include "elf/elfspace.h"
#include "segment.h"
#include "section.h"
#include "makeplt.h"

class ExeGen {
private:
    static const address_t CHOOSE_ADDRESS = static_cast<address_t>(-1);
    class Metadata {
    public:
        enum SegmentType {HEADER, PHDR_TABLE, RODATA, RWDATA, VISIBLE, INTERP, DYNAMIC, HIDDEN, SEGMENT_TYPES};
        enum StringTableType {SYM, SH, DYN, STRING_TABLE_TYPES};
    private:
        typedef std::vector<Segment *> SegmentList;
        typedef std::vector<Section *> StringTableList;
        SegmentList segmentList;
        StringTableList stringTableList;
    public:
        Metadata();
        ~Metadata();
    public:
        ConcreteIterable<SegmentList> getSegmentList() { return ConcreteIterable<SegmentList>(segmentList); }
        Segment *getSegment(SegmentType type) const { return segmentList[type]; }
        Segment * operator [](SegmentType type) const {return segmentList[type];}
        Section *getStrTable(StringTableType type) const { return stringTableList[type]; }
    };
private:
    ElfSpace *elfSpace;
    MemoryBacking *backing;
    std::string filename;
    const char *interpreter;
    Metadata data;
    MakeOriginalPLT originalPLT;
public:
    ExeGen(ElfSpace *space, MemoryBacking *backing, std::string filename,
        const char *interpreter = nullptr);
public:
    void generate();
private:
    void makeRWData();
    void makeText();
    void makeSymbolInfo();
    void makeDynamicSymbolInfo();
    void makePLT();
    void makeDynamic();
    void makePhdrTable();
    void makeShdrTable();
    void makeHeader();
    void updateOffsetAndAddress();
    void updateHeader();
    void serializeSegments();
private:
    size_t getNextFreeOffset();
    address_t getNextFreeAddress();
    static size_t roundUpToPageAlign(size_t address);
};

#endif
