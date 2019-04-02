#ifndef EGALITO_GENERATE_CONCRETE_H
#define EGALITO_GENERATE_CONCRETE_H

#include <string>
#include <vector>
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
private:
    bool addLibDependencies;
public:
    BasicElfStructure(bool addLibDependencies = false)
        : addLibDependencies(addLibDependencies) {}
    virtual void execute();
    virtual std::string getName() const { return "BasicElfStructure"; }
private:
    void makeHeader();
    void makeSymtabSection() ;
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

class Function;
class InitArraySectionContent;
class MakeInitArray : public NormalElfOperation {
private:
    int stage;

    // size of .init_array in bytes, used to offset .fini_array afterwards
    size_t initArraySize;
public:
    MakeInitArray(int stage);
    virtual void execute();
private:
    void makeInitArraySections();
    void makeInitArraySectionHelper(const char *type,
        InitArraySectionContent *content);
    void makeInitArraySectionLinks();
    void addInitFunction(InitArraySectionContent *content,
        std::function<address_t ()> value);
    Function *findLibcCsuInit(Chunk *entryPoint);
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

class UpdatePLTLinks : public NormalElfOperation {
public:
    UpdatePLTLinks() {}
    virtual void execute();
};

class CopyDynsym : public NormalElfOperation {
public:
    virtual void execute();
};

class MakeDynsymHash : public NormalElfOperation {
private:
    std::vector<std::vector<std::string>> bucketList;
    std::map<std::string, size_t> indexMap;
public:
    virtual void execute();
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
