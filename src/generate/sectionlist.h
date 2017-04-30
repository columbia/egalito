#ifndef EGALITO_GENERATE_SECTION_LIST_H
#define EGALITO_GENERATE_SECTION_LIST_H

#include <ostream>
#include <map>
#include <vector>
#include <functional>
#include "types.h"

class SectionList {
private:
    std::map<std::string, Section *> sectionMap;
    std::map<Section *, size_t> sectionIndexMap;
    std::vector<Section *> sections;
public:
    Sections() {}
    ~Sections();
public:
    void addSection(Section *section);
    std::vector<Section *>::iterator begin() { return sections.begin(); }
    std::vector<Section *>::iterator end() { return sections.end(); }
    Section *operator [] (std::string name);
    int indexOf(Section *section);
};

/** Section -> int deferred data. */
class SectionRef {
private:
    SectionList *list;
    std::string sectionName;
public:
    SectionRef(SectionList *list, const std::string &sectionName)
        : list(list), sectionName(sectionName) {}
    Section *get() const;
    int getIndex() const;
};

class StringRef {
private:
    std::string str;
public:
    StringRef(SectionList *list, const std::string &str)
        : list(list), str(str) {}
    size_t getIndex() const;
};

#endif
