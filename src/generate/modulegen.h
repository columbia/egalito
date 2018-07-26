#ifndef EGALITO_GENERATE_MODULEGEN_H
#define EGALITO_GENERATE_MODULEGEN_H

#include <string>
#include "types.h"
#include "section.h"
#include "sectionlist.h"

class Module;
class Function;
class MemoryBufferBacking;
class DataSection;

class ModuleGen {
public:
    class Config {
    private:
        bool isDynamicallyLinked;
        bool uniqueSectionNames;
        bool isFreestandingKernel;

        /** If generating a kernel, use a memory backing to store serialized
            code, avoiding mapping into invalid addresses. If null, read
            directly from mmaps.
        */
        MemoryBufferBacking *backing;
    public:
        Config() : isDynamicallyLinked(false), uniqueSectionNames(false),
            isFreestandingKernel(false), backing(nullptr) {}

        void setDynamicallyLinked(bool enable) 
            { isDynamicallyLinked = enable; }
        void setUniqueSectionNames(bool enable) 
            { uniqueSectionNames = enable; }
        void setCodeBacking(MemoryBufferBacking *backing)
            { this->backing = backing; }
        void setFreestandingKernel(bool enable)
            { this->isFreestandingKernel = enable; }
        
        bool getDynamicallyLinked() const { return isDynamicallyLinked; }
        bool getUniqueSectionNames() const { return uniqueSectionNames; }
        MemoryBufferBacking *getCodeBacking() const { return backing; }
        bool isKernel() const { return this->isFreestandingKernel; }
    };
private:
    Config config;
    Module *module;
    SectionList *sectionList;
public:
    ModuleGen(Config config, Module *module, SectionList *sectionList);

    void makeDataSections();

    void makeText();
    void makeTextAccumulative();
    void makeRelocSectionFor(const std::string &otherName);
    void maybeMakeDataRelocSection(DataSection *section, Section *sec);
    void makeSymbolsAndRelocs(address_t begin, size_t size,
        const std::string &textSection);
    void makeSymbolInText(Function *func, const std::string &textSection);
    void makeRelocInText(Function *func, const std::string &textSection);

    void makePaddingSection(size_t desiredAlignment);
private:
    size_t shdrIndexOf(Section *section);
    size_t shdrIndexOf(const std::string &name);
    static bool blacklistedSymbol(const std::string &name);

    Section *getSection(const std::string &name)
        { return (*sectionList)[name]; }
};

#endif
