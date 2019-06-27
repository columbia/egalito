#ifndef EGALITO_PE_MAKERELOC_H 
#define EGALITO_PE_MAKERELOC_H

class Reloc;
class RelocList;
class PEMap;
class SymbolList;

class PEMakeReloc {
public:
    static RelocList *buildRelocList(PEMap *peMap, SymbolList *symbolList,
        SymbolList *dynamicSymbolList = nullptr);
};

#endif
