#include <cstring>  // for memset
#include "section.h"
#include "sectionlist.h"
#include "elf/symbol.h"
#include "elf/elfxx.h"
#include "chunk/concrete.h"  // for Function
#include "log/log.h"

SectionHeader::SectionHeader(Section *outer, ElfXX_Word type,
    ElfXX_Xword flags) : outer(outer), address(0),
    shdrType(type), shdrFlags(flags), sectionLink(nullptr) {

}

Section::Section(const std::string &name, ElfXX_Word type,
    ElfXX_Xword flags) : name(name), offset(0), content(nullptr) {

    header = new SectionHeader(this, type, flags);
}

Section::Section(const std::string &name, DeferredValue *content)
    : name(name), offset(0), header(nullptr), content(content) {
}

std::ostream &operator << (std::ostream &stream, Section &rhs) {
    if(rhs.hasContent()) {
        rhs.getContent()->writeTo(stream);
    }
    return stream;
}
