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

Link *FindAnywhere::resolveAsLink(const Symbol *symbol) {
    if(!symbol) return nullptr;

    if(symbol->getBind() == Symbol::BIND_LOCAL) {
        auto addr = symbol->getAddress();
        auto func = CIter::spatial(elfSpace->getModule()->getFunctionList())
            ->findContaining(addr);
        if(func) {
            if(func->getAddress() == addr) {
                LOG(10, "must be pointing to a function");
                return new NormalLink(func);
            }
            else {
                LOG(10, "addr " << addr << " points inside " << func->getName());
                Chunk *inner = ChunkFind().findInnermostInsideInstruction(
                    func, addr);
                auto instruction = dynamic_cast<Instruction *>(inner);
                return new NormalLink(instruction);
            }
        }

        addr += elfSpace->getElfMap()->getBaseAddress();
        auto region = CIter::spatial(elfSpace->getModule()->getDataRegionList())
            ->findContaining(addr);
        if(!region) {
            LOG(1, "region NOT found");
        }
        else {
            return LinkFactory::makeDataLink(elfSpace->getModule(), addr, true);
        }
    }

    return resolveAsLinkByName(symbol);
}

Link *FindAnywhere::resolveAsLinkByName(const Symbol *symbol) {
    const char *name = symbol->getName();
    LOG(10, "SEARCH for " << name);

    std::string versionedName;
    if(auto ver = symbol->getVersion()) {
        versionedName.append(name);
        versionedName.push_back('@');
        if(!ver->isHidden()) versionedName.push_back('@');
        versionedName.append(ver->getName());
    }

    if(auto link = resolveNameAsLinkHelper(name, elfSpace)) {
        return link;
    }
    else if(versionedName.size() > 0) {
        LOG(10, "trying versioned name " << versionedName.c_str());
        if(auto link = resolveNameAsLinkHelper(versionedName.c_str(),
            elfSpace)) {

            return link;
        }
    }

    for(auto library : *conductor->getLibraryList()) {
        auto space = library->getElfSpace();
        if(space && space != elfSpace) {
            if(auto link = resolveNameAsLinkHelper(name, space)) {
                return link;
            }
            else if(versionedName.size() > 0) {
                LOG(10, "trying versioned name " << versionedName.c_str());
                if(auto link = resolveNameAsLinkHelper(versionedName.c_str(),
                    space)) {

                    return link;
                }
            }
        }
    }

    return nullptr;
}

Link *FindAnywhere::resolveNameAsLinkHelper(const char *name, ElfSpace *space) {
    auto f = CIter::named(space->getModule()->getFunctionList())
        ->find(name);
    if(f) {
        LOG(10, "    ...found as function! at "
            << std::hex << f->getAddress());
        return new NormalLink(f);
    }

    auto alias = space->getAliasMap()->find(name);
    if(alias) {
        LOG(10, "    ...found as alias! " << alias->getName()
            << " at " << std::hex << alias->getAddress());
        return new NormalLink(alias);
    }

    // we cannot make a link to emulator symbol yet
    if(auto a = LoaderEmulator::getInstance().findSymbol(name)) {
        LOG(10, "    ...found via emulation! at " << std::hex << a);
        return nullptr;
    }

    auto symbol = space->getSymbolList()->find(name);
    if(symbol) {
        if(symbol->getAddress() > 0
            && symbol->getType() != Symbol::TYPE_FUNC
            && symbol->getType() != Symbol::TYPE_IFUNC) {

            LOG(10, "    ...found as data ref! at "
                << std::hex << symbol->getAddress() << " in "
                << space->getModule()->getName());
            return LinkFactory::makeDataLink(space->getModule(),
                space->getElfMap()->getBaseAddress() + symbol->getAddress(),
                true);
        }
    }

    return nullptr;
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
#else
    address_t update = elfMap->getBaseAddress() + r->getAddress();
    address_t dest = 0;
    Link *link = nullptr;
    bool found = false;
    bool dontcare = false;
    size_t destOffset = 0;

    // There is a data variable for R_AARCH64_RELATIVE and R_AARCH64_TLS_TPREL

    if(r->getAddend() > 0) {
        auto addr = symbol->getAddress() + r->getAddend();
        // usually an offset from a section start address, or ...
        if(auto s = module->getElfSpace()->getSymbolList()->find(addr)) {
            symbol = s;
        }
        else {
            // pointing into the middle of an internal data object
            destOffset = r->getAddend();
        }
    }

    if(r->getType() == R_AARCH64_GLOB_DAT) {
        found = FindAnywhere(conductor, elfSpace).resolveName(symbol, &dest);
        link = FindAnywhere(conductor, elfSpace).resolveAsLink(symbol);
    }
    else if(r->getType() == R_AARCH64_JUMP_SLOT) {
        found = FindAnywhere(conductor, elfSpace).resolveName(symbol, &dest);
        link = FindAnywhere(conductor, elfSpace).resolveAsLink(symbol);
    }
    else if(r->getType() == R_AARCH64_ABS64) {
        found = FindAnywhere(conductor, elfSpace).resolveName(symbol, &dest);
        if(!found) {
            if(symbol->getType() == Symbol::TYPE_SECTION) {
                dest = symbol->getAddress();
                found = true;
            }
        }
        link = FindAnywhere(conductor, elfSpace).resolveAsLink(symbol);
    }
    else {
        dontcare = true;
        LOG(10, "    NOT fixing because type is " << r->getType());
    }
    if(link) {
        LOG0(1, "    make link: " << std::hex << update << " -> "
             << link->getTargetAddress());
        if(link->getTarget()) LOG(1, " " <<  link->getTarget()->getName());
        else LOG(1, "");
        auto list = module->getDataRegionList();
        auto sourceRegion = list->findRegionContaining(update);
        auto var = new DataVariable(sourceRegion, update, link);
        sourceRegion->addVariable(var);
        if(destOffset > 0) {
            var->setAddend(destOffset);
        }
    }
    else if(found) {
        LOG(10, "    fix address " << std::hex << update
            << " to point at " << dest << " + " << destOffset
            << " which was " << std::hex << *(unsigned long *)update);
        // unless it is pointing to a loader emulation object whose address
        // is fixed,
        LOG(1, "     data may not be moved: " << module->getName());
        *(unsigned long *)update = dest + destOffset;
    }
    else if(!dontcare) {
        LOG(1, "    not found!");
        LOG(1, "        offset " << std::hex << r->getAddress()
            << " addend " << r->getAddend());
    }
#endif
}
