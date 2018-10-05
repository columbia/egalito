#ifndef EGALITO_GENERATE_CONCRETE_H
#define EGALITO_GENERATE_CONCRETE_H

#include <string>
#include "data.h"

class BasicElfCreator : public UnnamedElfOperation {
public:
    virtual void execute();
    virtual std::string getName() const { return "BasicElfCreator"; }
};

class BasicElfStructure : public UnnamedElfOperation {
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
class AssignSectionsToSegments : public UnnamedElfOperation {
public:
    virtual void execute();
    virtual std::string getName() const { return "AssignSectionsToSegments"; }
};

// Can't make any new sections after this
class GenerateSectionTable : public UnnamedElfOperation {
public:
    virtual void execute();
    virtual std::string getName() const { return "GenerateSectionTable"; }
private:
    void makeShdrTable();
    void makeSectionSymbols();
};

class TextSectionCreator : public UnnamedElfOperation {
public:
    virtual void execute();
    virtual std::string getName() const { return "TextSectionCreator"; }
};

class MakeInitArray : public UnnamedElfOperation {
public:
    virtual void execute();
    virtual std::string getName() const { return "MakeInitArray"; }
private:
    void makeInitArraySections();
    void makeInitArraySectionLinks();
};

class ElfFileWriter : public UnnamedElfOperation {
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
