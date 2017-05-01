#ifndef EGALITO_GENERATE_SECTION_LIST_H
#define EGALITO_GENERATE_SECTION_LIST_H

#include <ostream>
#include <map>
#include <vector>
#include <functional>
#include "types.h"

class Section2;

class SectionList {
private:
    std::map<std::string, Section2 *> sectionMap;
    std::map<Section2 *, size_t> sectionIndexMap;
    std::vector<Section2 *> sections;
public:
    ~SectionList();
public:
    void addSection(Section2 *section);
    std::vector<Section2 *>::iterator begin() { return sections.begin(); }
    std::vector<Section2 *>::iterator end() { return sections.end(); }
    void insert(std::vector<Section2 *>::iterator it, Section2 *section);
    Section2 *operator [] (std::string name);
    int indexOf(Section2 *section);
    int indexOf(const std::string &sectionName);
};

/** Section -> int deferred data. */
class SectionRef {
private:
    SectionList *list;
    std::string sectionName;
public:
    SectionRef(SectionList *list, const std::string &sectionName)
        : list(list), sectionName(sectionName) {}
    Section2 *get() const;
    int getIndex() const;
};

#endif
