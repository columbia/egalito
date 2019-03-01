#ifndef EGALITO_CHUNK_RESOLVER_H
#define EGALITO_CHUNK_RESOLVER_H

#include "link.h"

class Reloc;
class Instruction;
class Conductor;
class ElfSpace;
class ExternalSymbol;
class SymbolVersion;
class SymbolList;

/** This resolver assumes that we have both relocations and symbols.
 */
class PerfectLinkResolver {
public:
    /* Resolve within the same module using address info in a relocation.
     * Only returns nullptr if undefined within the module. */
    Link *resolveInternally(Reloc *reloc, Module *module, bool weak,
        bool relative=true);

    /* Resolve outside the module using symbol info. */
    Link *resolveExternally(Symbol *symbol, Conductor *conductor,
        ElfSpace *elfSpace, bool weak, bool relative, bool afterMapping=false);
    Link *resolveExternally(ExternalSymbol *externalSymbol, Conductor *conductor,
        ElfSpace *elfSpace, bool weak, bool relative, bool afterMapping=false);

    /* Resolve within the same module using address obtained by data flow
     * analysis. */
    Link *resolveInferred(address_t address, Instruction *instruction,
        Module *module, bool relative);

private:
    Link *resolveExternally2(const char *name, const SymbolVersion *version,
        Conductor *conductor, ElfSpace *elfSpace, bool weak, bool relative,
        bool afterMapping);
    Link *resolveNameAsLinkHelper(const char *name, const SymbolVersion *version,
        ElfSpace *space, bool weak, bool relative, bool afterMapping);
    Link *resolveNameAsLinkHelper2(const char *name, ElfSpace *space,
        bool weak, bool relative, bool afterMapping);
public:
    Link *redirectCopyRelocs(Module *main, Symbol *symbol,
        SymbolList *list, bool relative);
    Link *redirectCopyRelocs(Module *main, ExternalSymbol *extSym,
        SymbolList *list, bool relative);
};

#endif
