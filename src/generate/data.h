#ifndef EGALITO_GENERATE_DATA_H
#define EGALITO_GENERATE_DATA_H

#include <map>
#include <set>
#include <vector>
#include <string>
#include "sectionlist.h"
#include "transform/sandbox.h"

class Program;
class ElfOperationTrace;
class PLTIndexMap;

class ElfData {
public:
    virtual ~ElfData() {}

    virtual Program *getProgram() const = 0;
    virtual SandboxBacking *getBacking() = 0;
    virtual SectionList *getSectionList() = 0;
    virtual Section *getSection(const std::string &name) = 0;
    virtual ElfOperationTrace *getOperationTrace() const = 0;
    virtual PLTIndexMap *getPLTIndexMap() const = 0;
};

class ElfDataImpl : public ElfData {
private:
    Program *program;
    SandboxBacking *backing;
    SectionList sectionList;
    ElfOperationTrace *opTrace;
    PLTIndexMap *pltIndexMap;
public:
    ElfDataImpl(Program *program, SandboxBacking *backing);
    virtual ~ElfDataImpl();

    virtual Program *getProgram() const { return program; }
    virtual SandboxBacking *getBacking() { return backing; }
    virtual SectionList *getSectionList() { return &sectionList; }
    virtual Section *getSection(const std::string &name)
        { return sectionList[name]; }
    virtual ElfOperationTrace *getOperationTrace() const { return opTrace; }
    virtual PLTIndexMap *getPLTIndexMap() const { return pltIndexMap; }
};

class ElfConfig {
private:
    bool dynamicallyLinked;
    bool positionIndependent;
    bool unionOutput;
    bool freestandingKernel;
public:
    ElfConfig() : dynamicallyLinked(false), positionIndependent(false),
        unionOutput(false), freestandingKernel(false) {}

    void setDynamicallyLinked(bool enable) { dynamicallyLinked = enable; }
    void setPositionIndependent(bool enable) { positionIndependent = enable; }
    void setUnionOutput(bool enable) { unionOutput = enable; }
    void setFreestandingKernel(bool enable) { freestandingKernel = enable; }

    bool isDynamicallyLinked() const { return dynamicallyLinked; }
    bool isPositionIndependent() const { return positionIndependent; }
    bool isUnionOutput() const { return unionOutput; }
    bool isFreestandingKernel() const { return freestandingKernel; }
};

class ElfOperationTrace {
private:
    std::map<std::string, int> executedCount;
    std::vector<std::string> traceOrder;

public:
    void add(const std::string &name);
    bool ran(const std::string &name);
};

class ElfOperation {
public:
    virtual ~ElfOperation() {}

    virtual std::string getName() const = 0;
    virtual void execute() = 0;
};

template <typename BaseType>
class ElfOperationNameDecorator : public BaseType {
private:
    std::string name;
public:
    ElfOperationNameDecorator(const std::string &name = "") : name(name) {}

    void setName(const std::string &name) { this->name = name; }
    virtual std::string getName() const { return name; }
};

template <typename BaseType>
class ElfOperationStorageDecorator : public BaseType {
private:
    ElfData *data;
    ElfConfig *config;
public:
    ElfOperationStorageDecorator() : data(nullptr), config(nullptr) {}
    ElfOperationStorageDecorator(ElfData *data, ElfConfig *config)
        : data(data), config(config) {}

    ElfData *getData() const { return data; }
    ElfConfig *getConfig() const { return config; }

    void setData(ElfData *data) { this->data = data; }
    void setConfig(ElfConfig *config) { this->config = config; }
};

typedef ElfOperationStorageDecorator<ElfOperation>
    UnnamedElfOperation;
typedef ElfOperationNameDecorator<UnnamedElfOperation>
    NormalElfOperation;

class ElfPipeline : public NormalElfOperation {
private:
    std::set<std::string> dependencyList;
    std::vector<ElfOperation *> pipeline;
public:
    ElfPipeline(ElfData *data, ElfConfig *config)
        { setData(data); setConfig(config); }

    void addDependency(const std::string &dep) { dependencyList.insert(dep); }
    void add(UnnamedElfOperation *op);

    virtual void execute();
private:
    void checkDependencies();
};

class PLTTrampoline;
class PLTIndexMap {
public:
    typedef std::map<PLTTrampoline *, size_t> EntryMap;
private:
    Section *pltSection;
    EntryMap entryMap;
public:
    PLTIndexMap() : pltSection(nullptr) {}

    Section *getPltSection() const { return pltSection; }
    void setPltSection(Section *section) { pltSection = section; }

    EntryMap &getEntryMap() { return entryMap; }
};

#endif
