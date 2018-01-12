#ifndef EGALITO_GENERATE_SECTION_LIST_H
#define EGALITO_GENERATE_SECTION_LIST_H

#include <ostream>
#include <map>
#include <vector>
#include <functional>
#include "types.h"

class Section;

/** Stores a list of all Sections that have been created. Sections may be
    iterated through or looked up by name. There is also a special index
    assigned to some sections, only those which will be visible in the final
    shdr list.
*/
class SectionList {
private:
    std::map<std::string, Section *> sectionMap;
    std::map<Section *, size_t> sectionIndexMap;
    std::vector<Section *> sections;
    size_t sectionCount;
public:
    SectionList() : sectionCount(1) {}
    ~SectionList();
public:
    void addSection(Section *section);
    std::vector<Section *>::iterator begin() { return sections.begin(); }
    std::vector<Section *>::iterator end() { return sections.end(); }
    void insert(std::vector<Section *>::iterator it, Section *section);
    Section *operator [] (std::string name);
    Section *back();
    int indexOf(Section *section);
    int indexOf(const std::string &sectionName);
private:
    static bool isAssignedAnIndex(Section *section);
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

#endif
