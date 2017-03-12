#include "relocdata.h"
#include "elf/elfmap.h"
#include "elf/reloc.h"
#include "chunk/aliasmap.h"
#include "conductor/conductor.h"
#include "load/emulator.h"
#include "log/log.h"

Function *FindAnywhere::findInside(Module *module, const char *target) {
    found = module->getChildren()->getNamed()->find(target);
    if(!found) {
        found = elfSpace->getAliasMap()->find(target);
    }
    return found;
}

Function *FindAnywhere::findAnywhere(const char *target) {
    if(!conductor) return nullptr;

    elfSpace = conductor->getMainSpace();
    found = findInside(elfSpace->getModule(), target);
    if(found) return found;

    for(auto library : *conductor->getLibraryList()) {
        elfSpace = library->getElfSpace();
        if(elfSpace) {
            found = findInside(elfSpace->getModule(), target);
            if(found) return found;
        }
    }

    LOG(1, "    could not find " << target << " ANYWHERE");
    return nullptr;
}

address_t FindAnywhere::getRealAddress() {
    return elfSpace->getElfMap()->getBaseAddress()
        + found->getAddress();
}

void RelocDataPass::visit(Module *module) {
    this->module = module;
    for(auto r : *relocList) {
        fixRelocation(r);
    }
}

bool RelocDataPass::resolveFunction(const char *name, address_t *address) {
    FindAnywhere found(conductor, elfSpace);
    Function *target = found.findInside(module, name);
    if(target) {
        *address = target->getAddress();
        return true;
    }

    target = found.findAnywhere(name);
    if(target) {
        *address = target->getAddress();
        return true;
    }

    if(auto a = LoaderEmulator::getInstance().findSymbol(name)) {
        *address = a;
        return true;
    }
    return false;
}

bool RelocDataPass::resolveLocalDataRef(const char *name,
    address_t *address) {

    Symbol *symbol = elfSpace->getSymbolList()->find(name);
    if(!symbol) return false;

    if(symbol->getType() == Symbol::TYPE_FUNC
        || symbol->getType() == Symbol::TYPE_IFUNC) {

        FindAnywhere found(conductor, elfSpace);
        Function *f = found.findInside(module, name);
        if(f) {
            *address = found.getRealAddress();
            return true;
        }
        return false;
    }

    // otherwise, must be a data object, address unchanged
    *address = elf->getBaseAddress()
        + symbol->getAddress();
    return true;
}

void RelocDataPass::fixRelocation(Reloc *r) {
    const char *name = 0;
    if(r->getSymbol() && *r->getSymbol()->getName()) {
        name = r->getSymbol()->getName();
    }

    LOG(1, "trying to fix " << (name ? name : "???"));

#ifdef ARCH_X86_64
    address_t update = elf->getBaseAddress() + r->getAddress();
    address_t dest = 0;
    bool found = false;

    if(r->getType() == R_X86_64_GLOB_DAT) {
        if(name) found = resolveLocalDataRef(name, &dest);
    }
    else if(r->getType() == R_X86_64_JUMP_SLOT) {
        if(name) found = resolveFunction(name, &dest);
    }
    else if(r->getType() == R_X86_64_RELATIVE) {
        found = true;
        dest = elf->getBaseAddress() + r->getAddend();
    }
    else {
        LOG(1, "NOT fixing because type is " << r->getType());
    }

    if(found) {
        LOG(1, "fix address " << update << " to point at " << dest);
        *(unsigned long *)update = dest;
    }
#endif
}
