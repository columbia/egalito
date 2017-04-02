#include <cassert>
#include "relocdata.h"
#include "elf/elfmap.h"
#include "elf/reloc.h"
#include "chunk/aliasmap.h"
#include "conductor/conductor.h"
#include "load/emulator.h"
#include "log/log.h"

bool FindAnywhere::resolveName(const char *name, address_t *address) {
    if(name) {
        //LOG(1, "SEARCH for " << name);

        // first check the elfSpace we are resolving relocations for
        if(resolveNameHelper(name, address, elfSpace)) return true;

        for(auto library : *conductor->getLibraryList()) {
            auto space = library->getElfSpace();
            if(space && space != elfSpace) {
                if(resolveNameHelper(name, address, space)) return true;
            }
        }

        auto mainSpace = conductor->getMainSpace();
        if(mainSpace != elfSpace) {
            if(resolveNameHelper(name, address, mainSpace)) return true;
        }
    }

    return false;
}

bool FindAnywhere::resolveObject(const char *name, address_t *address,
    size_t *size) {

    if(name) {
        // note: we do not check elfSpace, we're looking for an external target

        for(auto library : *conductor->getLibraryList()) {
            auto space = library->getElfSpace();
            if(space && space != elfSpace) {
                if(resolveObjectHelper(name, address, size, space)) return true;
            }
        }

        auto mainSpace = conductor->getMainSpace();
        if(mainSpace != elfSpace) {
            if(resolveObjectHelper(name, address, size, mainSpace)) return true;
        }
    }

    return false;
}

bool FindAnywhere::resolveNameHelper(const char *name, address_t *address,
    ElfSpace *space) {

    assert(name != nullptr);

    // First, check if this is a function we transformed;
    // if so, we should use the new address.
    auto f = CIter::named(space->getModule()->getFunctionList())
        ->find(name);
    if(f) {
        LOG(1, "    ...found as function! at "
            << std::hex << f->getAddress());
        *address = f->getAddress();
        return true;
    }

    // Also, check if this is an alias for a known function.
    auto alias = space->getAliasMap()->find(name);
    if(alias) {
        LOG(1, "    ...found as alias! at "
            << std::hex << alias->getAddress());
        *address = alias->getAddress();
        return true;
    }

    // Maybe this is normally supplied by the system loader and
    // we're supplying it instead.
    if(auto a = LoaderEmulator::getInstance().findSymbol(name)) {
        LOG(1, "    ...found via emulation! at " << std::hex << a);
        *address = a;
        return true;
    }

    // Lastly, see if this is a data object; if so, use the original
    // address (but add the new load address as a base address).
    auto symbol = space->getSymbolList()->find(name);
    if(symbol) {
        if(symbol->getAddress() > 0
            && symbol->getType() != Symbol::TYPE_FUNC
            && symbol->getType() != Symbol::TYPE_IFUNC) {

            // must be a data object, address unchanged
            LOG(1, "    ...found as data ref! at "
                << std::hex << symbol->getAddress());
            *address = space->getElfMap()->getBaseAddress()
                + symbol->getAddress();
            return true;
        }
    }

    return false;
}

bool FindAnywhere::resolveObjectHelper(const char *name, address_t *address,
    size_t *size, ElfSpace *space) {

    assert(name != nullptr);

    // Check if we have a data object.
    auto symbol = space->getSymbolList()->find(name);
    if(symbol) {
        if(symbol->getAddress() > 0
            && symbol->getType() != Symbol::TYPE_FUNC
            && symbol->getType() != Symbol::TYPE_IFUNC) {

            // we found it
            LOG(1, "    ...found data object! at "
                << std::hex << symbol->getAddress());
            *address = space->getElfMap()->getBaseAddress()
                + symbol->getAddress();
            *size = symbol->getSize();
            return true;
        }
    }

    return false;
}


void RelocDataPass::visit(Module *module) {
    this->module = module;
    for(auto r : *relocList) {
        fixRelocation(r);
    }
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

    LOG(1, "trying to fix " << (name ? name : "???")
        << " reloc type " << std::dec << (int)r->getType());

#ifdef ARCH_X86_64
    address_t update = elf->getBaseAddress() + r->getAddress();
    address_t dest = 0;
    bool found = false;

    if(r->getType() == R_X86_64_GLOB_DAT) {
        found = FindAnywhere(conductor, elfSpace).resolveName(name, &dest);
    }
    else if(r->getType() == R_X86_64_JUMP_SLOT) {
        found = FindAnywhere(conductor, elfSpace).resolveName(name, &dest);
    }
    else if(r->getType() == R_X86_64_PLT32) {
        // don't update refs to original PLT entries in original code
#if 0
        if(FindAnywhere(conductor, elfSpace).resolveName(name, &dest)) {
            LOG(1, "    fix address " << std::hex << update
                << " to point at " << dest);
            *(unsigned int *)update = dest;
        }
#endif
    }
    else if(r->getType() == R_X86_64_PC32) {
        // don't update function pointers in original code
    }
    else if(r->getType() == R_X86_64_64) {
        found = FindAnywhere(conductor, elfSpace).resolveName(name, &dest);
    }
    else if(r->getType() == R_X86_64_RELATIVE) {
        found = FindAnywhere(conductor, elfSpace).resolveName(name, &dest);
        if(!found) {
            dest = elf->getBaseAddress() + r->getAddend();
            found = true;
        }
    }
    else if(r->getType() == R_X86_64_TPOFF64) {
        // stores an index into the thread-local storage table at %fs
        dest = r->getAddend();
        found = true;
    }
    else if(r->getType() == R_X86_64_COPY) {
        address_t other;
        size_t otherSize;
        found = FindAnywhere(conductor, elfSpace).resolveObject(name, &other, &otherSize);
        if(found) {
            size_t size = std::min(otherSize, r->getSymbol()->getSize());
            LOG(1, "    doing memcpy from " << other
                << " to " << update << " size " << size);
            std::memcpy((void *)update, (void *)other, size);
        }
        found = false;
    }
    else {
        LOG(1, "    NOT fixing because type is " << r->getType());
    }

    if(found) {
        LOG(1, "    fix address " << std::hex << update
            << " to point at " << dest);
        *(unsigned long *)update = dest;
    }
#else
    address_t update = elf->getBaseAddress() + r->getAddress();
    address_t dest = 0;
    bool found = false;
    if(r->getType() == R_AARCH64_GLOB_DAT) {
        found = FindAnywhere(conductor, elfSpace).resolveName(name, &dest);
    }
    else if(r->getType() == R_AARCH64_JUMP_SLOT) {
        found = FindAnywhere(conductor, elfSpace).resolveName(name, &dest);
    }
    else if(r->getType() == R_AARCH64_RELATIVE) {
        found = FindAnywhere(conductor, elfSpace).resolveName(name, &dest);
        if(!found) {
            dest = elf->getBaseAddress() + r->getAddend();
            found = true;
        }
    }
    else if(r->getType() == R_AARCH64_PREL32) {
        LOG(1, "PREL32 isn't handled yet");
    }
    else if(r->getType() == R_AARCH64_TLS_TPREL) {
        dest = r->getAddend();
    }
    else if(r->getType() == R_AARCH64_ABS64) {
        found = FindAnywhere(conductor, elfSpace).resolveName(name, &dest);
    }
    else {
        LOG(1, "    NOT fixing because type is " << r->getType());
    }
    if(found) {
        LOG(1, "    fix address " << std::hex << update
            << " to point at " << dest
            << " which was " << std::hex << *(unsigned long *)update);
        *(unsigned long *)update = dest;
    }
    else {
        LOG(1, "    not found!");
    }
#endif
}
