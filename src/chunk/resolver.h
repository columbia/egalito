#ifndef EGALITO_CHUNK_RESOLVER_H
#define EGALITO_CHUNK_RESOLVER_H

#include "link.h"

class Reloc;
class Instruction;
class Conductor;
class Module;
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
    Link *resolveExternallyStrongWeak(Symbol *symbol, Conductor *conductor,
        Module *module, bool relative, bool afterMapping=false);
    Link *resolveExternallyStrongWeak(ExternalSymbol *externalSymbol, Conductor *conductor,
        Module *module, bool relative, bool afterMapping=false);

    Link *resolveExternally(Symbol *symbol, Conductor *conductor,
        Module *module, bool weak, bool relative, bool afterMapping=false);
    Link *resolveExternally(ExternalSymbol *externalSymbol, Conductor *conductor,
        Module *module, bool weak, bool relative, bool afterMapping=false);
    Link *resolveExternally(ExternalSymbol *externalSymbol, Conductor *conductor,
        Module *module, int addend, bool weak, bool relative, bool afterMapping=false);

    /* Resolve within the same module using address obtained by data flow
     * analysis. */
    Link *resolveInferred(address_t address, Instruction *instruction,
        Module *module, bool relative);

private:
    Link *resolveExternallyHelper(const char *name, const SymbolVersion *version,
        Conductor *conductor, Module *module, int addend, bool weak, bool relative,
        bool afterMapping);
    Link *resolveNameAsLinkHelper(const char *name, const SymbolVersion *version,
        Module *module, int addend, bool weak, bool relative, bool afterMapping);
    Link *resolveNameAsLinkHelper2(const char *name, Module *module,
        int addend, bool weak, bool relative, bool afterMapping);
public:
    // redirectCopyRelocs assumes afterMapping=true
    Link *redirectCopyRelocs(Conductor *conductor, Symbol *symbol, bool relative);
    Link *redirectCopyRelocs(Conductor *conductor, ExternalSymbol *symbol, bool relative);
    Link *redirectCopyRelocs(Module *main, Symbol *symbol,
        SymbolList *list, bool relative);
    Link *redirectCopyRelocs(Module *main, ExternalSymbol *extSym,
        SymbolList *list, bool relative);
};

#endif
