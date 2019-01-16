#ifndef EGALITO_GENERATE_CONCRETE_H
#define EGALITO_GENERATE_CONCRETE_H

#include <string>
#include "data.h"

class ConcreteElfOperation : public UnnamedElfOperation {
protected:
    Section *getSection(const std::string &name) const
        { return getData()->getSection(name); }
    SectionList *getSectionList() const { return getData()->getSectionList(); }
};

class BasicElfCreator : public ConcreteElfOperation {
private:
    bool makeInitArray;
public:
    BasicElfCreator(bool makeInitArray = true) : makeInitArray(makeInitArray) {}
    virtual void execute();
    virtual std::string getName() const { return "BasicElfCreator"; }
};

class BasicElfStructure : public ConcreteElfOperation {
public:
    virtual void execute();
    virtual std::string getName() const { return "BasicElfStructure"; }
private:
    void makeHeader();
    void makeSymtabSection();
    void makePhdrTable();
    void makeDynamicSection();
};

// Can't change size of certain sections after this
class AssignSectionsToSegments : public ConcreteElfOperation {
public:
    virtual void execute();
    virtual std::string getName() const { return "AssignSectionsToSegments"; }
};

// Can't make any new sections after this
class GenerateSectionTable : public ConcreteElfOperation {
public:
    virtual void execute();
    virtual std::string getName() const { return "GenerateSectionTable"; }
private:
    void makeShdrTable();
    void makeSectionSymbols();
};

class TextSectionCreator : public ConcreteElfOperation {
public:
    virtual void execute();
    virtual std::string getName() const { return "TextSectionCreator"; }
};

class MakeInitArray : public NormalElfOperation {
private:
    int stage;
public:
    MakeInitArray(int stage);
    virtual void execute();
private:
    void makeInitArraySections();
    void makeInitArraySectionLinks();
};

class PLTTrampoline;
class MakeGlobalPLT : public NormalElfOperation {
private:
    std::vector<PLTTrampoline *> entries;
    Section *gotpltSection;
public:
    virtual void execute();
private:
    void collectPLTEntries();
    void makePLTData();
    void makePLTCode();
};

class ElfFileWriter : public ConcreteElfOperation {
private:
    std::string filename;
public:
    ElfFileWriter(const std::string &filename) : filename(filename) {}

    virtual void execute();
    virtual std::string getName() const { return "ElfFileWriter"; }
private:
    void updateOffsets();
    void serialize();
};


class MakePaddingSection : public NormalElfOperation {
private:
    size_t desiredAlignment;
    bool isIsolatedPadding;
public:
    MakePaddingSection(size_t desiredAlignment, bool isIsolatedPadding = true);

    virtual void execute();
};



#endif
