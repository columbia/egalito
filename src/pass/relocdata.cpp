#include <cstring>
#include <cassert>
#include "relocdata.h"
#include "elf/elfmap.h"
#include "elf/reloc.h"
#include "chunk/aliasmap.h"
#include "chunk/link.h"
#include "conductor/conductor.h"
#include "load/emulator.h"
#include "operation/find.h"

#undef DEBUG_GROUP
#define DEBUG_GROUP dloadtime
#include "log/log.h"
#include "log/registry.h"
#include "log/temp.h"
#include "chunk/dump.h"

bool FindAnywhere::resolveName(const Symbol *symbol, address_t *address,
    bool allowInternal) {

    if(symbol) {
        const char *name = symbol->getName();
        LOG(10, "SEARCH for " << name << ", internal = " << allowInternal);

        std::string versionedName;
        if(auto ver = symbol->getVersion()) {
            versionedName.append(name);
            versionedName.push_back('@');
            if(!ver->isHidden()) versionedName.push_back('@');
            versionedName.append(ver->getName());
        }

        if(!allowInternal) {
            LOG(10, "skipping searching in " << elfSpace->getModule()->getName());
        }

        // first check the elfSpace we are resolving relocations for
        if(allowInternal) {
            if(resolveNameHelper(name, address, elfSpace)) {
                return true;
            }
            else if(versionedName.size() > 0) {
                LOG(10, "trying versioned name " << versionedName.c_str());
                if(resolveNameHelper(versionedName.c_str(), address, elfSpace)) {
                    return true;
                }
            }
        }

        for(auto library : *conductor->getLibraryList()) {
            auto space = library->getElfSpace();
            if(space && space != elfSpace) {
                if(resolveNameHelper(name, address, space)) {
                    return true;
                }
                else if(versionedName.size() > 0) {
                    LOG(10, "trying versioned name " << versionedName.c_str());
                    if(resolveNameHelper(versionedName.c_str(), address, space)) {
                        return true;
                    }
                }
            }
        }

#if 0
        auto mainSpace = conductor->getMainSpace();
        if(mainSpace != elfSpace) {
            if(resolveNameHelper(name, address, mainSpace)) return true;
        }
#endif
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

#if 0
        auto mainSpace = conductor->getMainSpace();
        if(mainSpace != elfSpace) {
            if(resolveObjectHelper(name, address, size, mainSpace)) return true;
        }
#endif
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
        LOG(10, "    ...found as function! at "
            << std::hex << f->getAddress());
        *address = f->getAddress();
        return true;
    }

    // Also, check if this is an alias for a known function.
    auto alias = space->getAliasMap()->find(name);
    if(alias) {
        LOG(10, "    ...found as alias! at "
            << std::hex << alias->getAddress());
        *address = alias->getAddress();
        return true;
    }

    // Maybe this is normally supplied by the system loader and
    // we're supplying it instead.
    if(auto a = LoaderEmulator::getInstance().findSymbol(name)) {
        LOG(10, "    ...found via emulation! at " << std::hex << a);
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
            LOG(10, "    ...found as data ref! at "
                << std::hex << symbol->getAddress() << " in "
                << space->getModule()->getName());
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
            LOG(10, "    ...found data object! at "
                << std::hex << symbol->getAddress() << " in "
                << space->getModule()->getName());
            *address = space->getElfMap()->getBaseAddress()
                + symbol->getAddress();
            *size = symbol->getSize();
            return true;
        }
    }

    return false;
}

void RelocDataPass::visit(Program *program) {
    // resolve relocations in library-depends order (because e.g. COPY relocs)

    std::set<SharedLib *> resolved;
    for(;;) {
        bool didWork = false;
        for(auto module : CIter::children(program)) {
            auto sharedLib = module->getElfSpace()->getLibrary();
            if(resolved.find(sharedLib) != resolved.end()) {
                continue;  // already processed this module
            }

            bool canResolve = true;
            for(auto dep : sharedLib->getDependencyList()) {
                if(resolved.find(dep) == resolved.end()) {
                    canResolve = false;
                    break;
                }
            }

            if(canResolve) {
                visit(module);
                didWork = true;
                resolved.insert(sharedLib);
            }
        }
        if(!didWork) break;
    }

    for(auto lib : *conductor->getLibraryList()) {
        if(resolved.find(lib) == resolved.end()) {
            LOG(0, "ERROR: did not resolve relocs in "
                << lib->getShortName() << " due to circular dependencies");
        }
    }
}

void RelocDataPass::visit(Module *module) {
    //TemporaryLogLevel tll("dloadtime", 10);
    LOG(10, "RESOLVING relocs for " << module->getName());
    this->elfSpace = module->getElfSpace();
    this->module = module;
    for(auto r : *elfSpace->getRelocList()) {
        fixRelocation(r);
    }
}

void RelocDataPass::fixRelocation(Reloc *r) {
    const char *name = 0;
    Symbol *symbol = r->getSymbol(); // we need symbol even if it has no name
    if(r->getSymbol() && *r->getSymbol()->getName()) {
        name = r->getSymbol()->getName();
    }
    else {
        // If the symbols are split into a separate file, the relocation
        // may not know its name, but we can find it.
        auto otherSym = elfSpace->getSymbolList()->find(r->getAddend());
        if(otherSym) {
            name = otherSym->getName();
            symbol = otherSym;
        }
    }

    LOG(10, "trying to fix " << (name ? name : "???")
        << " (" << std::hex << r->getAddress() << ")"
        << " reloc type " << std::dec << (int)r->getType());

    auto elfMap = elfSpace->getElfMap();

#ifdef ARCH_X86_64
    address_t update = elfMap->getBaseAddress() + r->getAddress();
    address_t dest = 0;
    bool found = false;

    if(r->getType() == R_X86_64_GLOB_DAT) {
        found = FindAnywhere(conductor, elfSpace).resolveName(symbol, &dest);
    }
    else if(r->getType() == R_X86_64_JUMP_SLOT) {
        found = FindAnywhere(conductor, elfSpace).resolveName(symbol, &dest);
    }
    else if(r->getType() == R_X86_64_PLT32) {
        // don't update refs to original PLT entries in original code
#if 0
        if(FindAnywhere(conductor, elfSpace).resolveName(symbol, &dest)) {
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
        found = FindAnywhere(conductor, elfSpace).resolveName(symbol, &dest);
    }
    else if(r->getType() == R_X86_64_RELATIVE) {
        found = FindAnywhere(conductor, elfSpace).resolveName(symbol, &dest);
        if(!found) {
            dest = elfMap->getBaseAddress() + r->getAddend();
            found = true;
        }
    }
    else if(r->getType() == R_X86_64_IRELATIVE) {
        found = FindAnywhere(conductor, elfSpace).resolveName(symbol, &dest);
        if(!found) {
            dest = elfMap->getBaseAddress() + r->getAddend();
            found = true;
        }
    }
    else if(r->getType() == R_X86_64_TPOFF64) {
        // stores an index into the thread-local storage table at %fs
        auto tls = module->getDataRegionList()->getTLS();
        if(tls) {
            dest = tls->getTLSOffset() + r->getAddend();
            found = true;
        }
    }
    else if(r->getType() == R_X86_64_COPY) {
        LOG(10, "IT'S A COPY! " << std::hex << update);
        address_t other;
        size_t otherSize = (size_t)-1;
        //found = FindAnywhere(conductor, elfSpace).resolveObject(name, &other, &otherSize);
        // do not allow internal references for COPY relocs
        found = FindAnywhere(conductor, elfSpace).resolveName(symbol, &other, false);
        if(found) {
            size_t size = std::min(otherSize, r->getSymbol()->getSize());
            LOG(10, "    doing memcpy from " << other
                << " (" << module->getName() << ")"
                << " to " << update << " size " << size);
            std::memcpy((void *)update, (void *)other, size);
            LOG(10, "        copied value " << *(unsigned long *)other);
        }
        found = false;
    }
    else {
        LOG(10, "    NOT fixing because type is " << r->getType());
    }

    if(found) {
        LOG(10, "    fix address " << std::hex << update
            << " to point at " << dest);
        *(unsigned long *)update = dest;
    }
    else {
        LOG(1, "    FAILED FIXING relocation at " << std::hex << r->getAddress());
    }
#else
    address_t update = elfMap->getBaseAddress() + r->getAddress();
    Link *link = nullptr;
    //size_t destOffset = 0;

#if defined(R_AARCH64_TLS_TPREL64) && !defined(R_AARCH64_TLS_TPREL)
    #define R_AARCH64_TLS_TPREL R_AARCH64_TLS_TPREL64
#endif
    if(r->getType() == R_AARCH64_TLS_TPREL
        || r->getType() == R_AARCH64_TLSDESC) {

        return; // will be handled in FixDataRegions
    }

    auto list = module->getDataRegionList();
    auto sourceRegion = list->findRegionContaining(update);
    if(!sourceRegion) {
        return;
    }
    auto sourceSection = sourceRegion->findDataSectionContaining(update);
    if(!sourceSection || sourceSection->isCode()) {
        return;
    }
    auto variable = sourceRegion->findVariable(update);
    if(variable && variable->getDest()->getTarget()) {
        return;
    }

    if(symbol->isMarker()) {
        return;
    }

    if(r->getAddend() > 0) {
        auto addr = symbol->getAddress() + r->getAddend();
        if(auto s = module->getElfSpace()->getSymbolList()->find(addr)) {
            symbol = s;
        }
#if 0
        else {
            // pointing into the middle of an internal data object
            destOffset = r->getAddend();
        }
#endif
    }

    link = PerfectLinkResolver::resolveExternally(symbol, conductor, elfSpace);

    // these shouldn't be necessary as long as relocations are available
#if 0
    address_t dest = 0;
    bool found = false;

    if(r->getType() == R_AARCH64_GLOB_DAT) {
        found = FindAnywhere(conductor, elfSpace).resolveName(symbol, &dest);
    }
    else if(r->getType() == R_AARCH64_JUMP_SLOT) {
        found = FindAnywhere(conductor, elfSpace).resolveName(symbol, &dest);
    }
    else if(r->getType() == R_AARCH64_ABS64) {
        found = FindAnywhere(conductor, elfSpace).resolveName(symbol, &dest);
        if(!found) {
            if(symbol->getType() == Symbol::TYPE_SECTION) {
                dest = symbol->getAddress();
                found = true;
            }
        }
    }
#endif

    if(link) {
        //TemporaryLogLevel tll("pass", 10);
        LOG0(10, "    make link: " << std::hex << update << " -> "
             << link->getTargetAddress());
        if(link->getTarget()) LOG(10, " " <<  link->getTarget()->getName());
        else LOG(10, "");
        auto list = module->getDataRegionList();
        auto sourceRegion = list->findRegionContaining(update);
        if(variable) {
            auto oldLink = variable->getDest();
            variable->setDest(link);
            delete oldLink;
        }
        else {
            variable = new DataVariable(sourceRegion, update, link);
            sourceRegion->addVariable(variable);
        }
    }
#if 0
    else if(found) {
        LOG(10, "    fix address " << std::hex << update
            << " to point at " << dest << " + " << destOffset
            << " which was " << std::hex << *(unsigned long *)update);
        // unless it is pointing to a loader emulation object whose address
        // is fixed,
        LOG(1, "     data may not be moved: " << module->getName());
        *(unsigned long *)update = dest + destOffset;
    }
#endif
    else {
        LOG(1, "    link not made! (is not an error if unused)");
        LOG(1, "        offset " << std::hex << r->getAddress()
            << " addend " << r->getAddend());
    }
#endif
}
