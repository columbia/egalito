#include "sectionlist.h"
#include "section.h"

SectionList::~SectionList() {
    for(auto section : sections) {
        delete section;
    }
}

void SectionList::addSection(Section2 *section) {
    sectionMap[section->getName()] = section;
    sectionIndexMap[section] = sections.size();
    sections.push_back(section);
}

Section2 *SectionList::operator [] (std::string name) {
    auto it = sectionMap.find(name);
    return (it != sectionMap.end() ? (*it).second : nullptr);
}

int SectionList::indexOf(Section2 *section) {
    return sectionIndexMap[section];
}

int SectionList::indexOf(const std::string &sectionName) {
    auto found = operator [] (sectionName);
    return (found ? sectionIndexMap[found] : -1);
}

Section2 *SectionRef::get() const {
    return (*list)[sectionName];
}

int SectionRef::getIndex() const {
    auto section = get();
    return (section ? list->indexOf(section) : -1);
}
