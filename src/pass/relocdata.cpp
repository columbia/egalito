#include <cassert>
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
    return found->getAddress();
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

bool RelocDataPass::resolveGen2Helper(const char *name, address_t *address,
    ElfSpace *space) {

    assert(name != nullptr);

#if 0
    auto symbol = space->getSymbolList()->find(name);
    if(symbol) {
        LOG(1, "found symbol [" << symbol->getName() << "]");

        // if the symbol is a function, its address has changed
        if(symbol->getType() == Symbol::TYPE_FUNC
            || symbol->getType() == Symbol::TYPE_IFUNC) {

            LOG(1, "SEARCH for function called [" << name << "]");

            FindAnywhere found(conductor, space);
            Function *f = found.findInside(module, name);
            if(f) {
                LOG(1, "...found! at " << found.getRealAddress());
                *address = found.getRealAddress();
                return true;
            }
        }
        else {
            // otherwise, must be a data object, address unchanged
            *address = elf->getBaseAddress() + symbol->getAddress();
            return true;
        }
    }

    auto alias = space->getAliasMap()->find(name);
    if(alias) {
        *address = alias->getAddress();
        return true;
    }

    return false;
#else
    auto f = space->getModule()->getChildren()->getNamed()->find(name);
    if(f) {
        LOG(1, "...found as function! at " << f->getAddress());
        *address = f->getAddress();
        return true;
    }

    auto alias = space->getAliasMap()->find(name);
    if(alias) {
        LOG(1, "...found as alias! at " << alias->getAddress());
        *address = alias->getAddress();
        return true;
    }

    if(auto a = LoaderEmulator::getInstance().findSymbol(name)) {
        LOG(1, "...found via emulation! at " << a);
        *address = a;
        return true;
    }

    auto symbol = space->getSymbolList()->find(name);
    if(symbol) {
        if(symbol->getAddress() > 0
            && symbol->getType() != Symbol::TYPE_FUNC
            && symbol->getType() != Symbol::TYPE_IFUNC) {

            // must be a data object, address unchanged
            LOG(1, "...found as data ref! at " << symbol->getAddress());
            *address = elf->getBaseAddress() + symbol->getAddress();
            return true;
        }
    }

    return false;
#endif
}

bool RelocDataPass::resolveGen2(const char *name, address_t *address) {
    if(name) {
        LOG(1, "SEARCH for " << name);

        if(resolveGen2Helper(name, address, elfSpace)) return true;

        for(auto library : *conductor->getLibraryList()) {
            auto space = library->getElfSpace();
            if(space && space != elfSpace) {
                if(resolveGen2Helper(name, address, space)) return true;
            }
        }
    }

    return false;
}

void RelocDataPass::fixRelocation(Reloc *r) {
    const char *name = 0;
    if(r->getSymbol() && *r->getSymbol()->getName()) {
        name = r->getSymbol()->getName();
    }
    else {
        // If the symbols are split into a separate file, the relocation
        // may not know its name, but we can find it.
        auto otherSym = elfSpace->getSymbolList()->find(r->getAddend());
        if(otherSym) name = otherSym->getName();
    }

    if(name && !strcmp(name, "__libc_start_main")) {
        LOG(1, "fixing ref to __libc_start_main, type = " << r->getType());
    }

    if(r->getAddress() == 0x397d80) {
        LOG(1, "DEBUG tpoff");
    }

    LOG(1, "trying to fix " << (name ? name : "???")
        << " reloc type " << std::dec << (int)r->getType());

#ifdef ARCH_X86_64
    address_t update = elf->getBaseAddress() + r->getAddress();
    address_t dest = 0;
    bool found = false;

    if(r->getAddress() == 0x397ef0) {
        LOG(1, "DEBUG");
    }

    if(r->getType() == R_X86_64_GLOB_DAT) {
        //if(name) found = resolveFunction(name, &dest);
        found = resolveGen2(name, &dest);
    }
    else if(r->getType() == R_X86_64_JUMP_SLOT) {
        //if(name) found = resolveFunction(name, &dest);
        found = resolveGen2(name, &dest);
    }
    else if(r->getType() == R_X86_64_RELATIVE) {
        found = resolveGen2(name, &dest);
        if(!found) {
            dest = elf->getBaseAddress() + r->getAddend();
            found = true;
        }
    }
    else if(r->getType() == R_X86_64_64) {
        found = resolveGen2(name, &dest);
    }
    else if(r->getType() == R_X86_64_TPOFF64) {
        // stores an index into the thread-local storage table at %fs
        found = true;
        dest = r->getAddend();
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
