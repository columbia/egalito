#ifndef EGALITO_EXEFILE_EXEFILE_H
#define EGALITO_EXEFILE_EXEFILE_H

#include <string>

#include "exemap.h"
#include "elf/elfmap.h"
#include "pe/pemap.h"

class SymbolList;
class RelocList;

class ExeFile {
public:
    enum ExeFileType {
        EXE_ELF,
        EXE_PE,
        EXE_UNKNOWN
    };
public:
    virtual ~ExeFile() {}

    virtual void parseSymbolsAndRelocs() = 0;
    virtual void parseSymbolsAndRelocs(const std::string &symbolFile) = 0;

    virtual ExeFileType getFileType() const = 0;
    virtual ExeMap *getMap() const = 0;

    virtual std::string getName() const = 0;
    virtual std::string getFullPath() const = 0;

    virtual SymbolList *getSymbolList() const = 0;
    virtual SymbolList *getDynamicSymbolList() const = 0;
    virtual RelocList *getRelocList() const = 0;
};

template <typename MapType, ExeFile::ExeFileType FileType = ExeFile::EXE_UNKNOWN>
class ExeFileImpl : public ExeFile {
private:
    MapType *map;
    std::string name;
    std::string fullPath;
public:
    ExeFileImpl(MapType *map, const std::string &name,
        const std::string &fullPath) : map(map), name(name), fullPath(fullPath) {}
    virtual ~ExeFileImpl() { delete map; }

    virtual void parseSymbolsAndRelocs() { parseSymbolsAndRelocs(""); }
    virtual void parseSymbolsAndRelocs(const std::string &symbolFile) = 0;

    virtual ExeFileType getFileType() const { return FileType; }
    virtual MapType *getMap() const { return map; }

    virtual std::string getName() const { return name; }
    virtual std::string getFullPath() const { return fullPath; }
};

template <typename BaseType, typename SymbolListT = SymbolList,
    typename RelocListT = RelocList>
class SymbolRelocExeFileDecorator : public BaseType {
private:
    SymbolListT *symbolList;
    SymbolListT *dynamicSymbolList;
    RelocListT *relocList;
public:
    using BaseType::BaseType;
    virtual SymbolListT *getSymbolList() const { return symbolList; }
    virtual SymbolListT *getDynamicSymbolList() const { return dynamicSymbolList; }
    virtual RelocListT *getRelocList() const { return relocList; }
protected:
    void setSymbolList(SymbolListT *list) { symbolList = list; }
    void setDynamicSymbolList(SymbolListT *list) { dynamicSymbolList = list; }
    void setRelocList(RelocListT *list) { relocList = list; }
};

class DwarfUnwindInfo;
class FunctionAliasMap;

class ElfExeFile : public SymbolRelocExeFileDecorator<ExeFileImpl<
    ElfMap, ExeFile::EXE_ELF>> {
private:
    DwarfUnwindInfo *dwarf;
    FunctionAliasMap *aliasMap;
public:
    ElfExeFile(ElfMap *elf, const std::string &name, const std::string &fullPath)
        : SymbolRelocExeFileDecorator<ExeFileImpl<ElfMap, ExeFile::EXE_ELF>>(
        elf, name, fullPath), dwarf(nullptr), aliasMap(nullptr) {}

    virtual void parseSymbolsAndRelocs(const std::string &symbolFile);

    DwarfUnwindInfo *getDwarfInfo() const { return dwarf; }

    FunctionAliasMap *getAliasMap() const { return aliasMap; }
    void setAliasMap(FunctionAliasMap *aliasMap) { this->aliasMap = aliasMap; }
private:
    std::string getAlternativeSymbolFile() const;
};

class PEExeFile : public SymbolRelocExeFileDecorator<ExeFileImpl<
    PEMap, ExeFile::EXE_PE>> {
public:
    PEExeFile(PEMap *pe, const std::string &name, const std::string &fullPath)
        : SymbolRelocExeFileDecorator<ExeFileImpl<PEMap, ExeFile::EXE_PE>>(
        pe, name, fullPath) {}

    virtual void parseSymbolsAndRelocs(const std::string &symbolFile);
};

#endif
