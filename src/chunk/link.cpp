#include "link.h"
#include "chunk/concrete.h"
#include "chunk/aliasmap.h"
#include "conductor/conductor.h"
#include "elf/reloc.h"
#include "elf/elfspace.h"
#include "load/emulator.h"
#include "operation/find.h"

#include "log/log.h"
#include "log/temp.h"

address_t NormalLink::getTargetAddress() const {
    return target->getAddress();
}

address_t OffsetLink::getTargetAddress() const {
    return target->getAddress() + offset;
}

address_t PLTLink::getTargetAddress() const {
    return pltTrampoline->getAddress();
}

ChunkRef JumpTableLink::getTarget() const {
    return jumpTable;
}

address_t JumpTableLink::getTargetAddress() const {
    return jumpTable->getAddress();
}

address_t MarkerLink::getTargetAddress() const {
    return marker->getAddress() + addend;
}

ChunkRef DataOffsetLink::getTarget() const {
    return section;
}

address_t DataOffsetLink::getTargetAddress() const {
    return section->getAddress() + target;
}

ChunkRef TLSDataOffsetLink::getTarget() const {
    return tls;
}

address_t TLSDataOffsetLink::getTargetAddress() const {
    return tls->getTLSOffset() + target;
}

Link *LinkFactory::makeNormalLink(ChunkRef target, bool isRelative,
    bool isExternal) {

    if(!isExternal) {
        if(isRelative) {
            return new NormalLink(target);
        }
        else {
            return new AbsoluteNormalLink(target);
        }
    }
    else {
        if(isRelative) {
            return new ExternalNormalLink(target);
        }
        else {
            return new ExternalAbsoluteNormalLink(target);
        }
    }
}

Link *LinkFactory::makeDataLink(Module *module, address_t target,
    bool isRelative) {

    return module->getDataRegionList()->createDataLink(
        target, module, isRelative);
}

Link *LinkFactory::makeMarkerLink(Module *module, address_t target,
    Symbol *symbol) {

    return module->getMarkerList()->createMarkerLink(
        target, 0, symbol, module);
}

Link *PerfectLinkResolver::resolveInternally(Reloc *reloc, Module *module,
    bool weak) {

    address_t addr = reloc->getAddend();
    if(auto symbol = reloc->getSymbol()) {
        LOG(10, "(resolveInternally) SEARCH for " << symbol->getName());

        if(symbol->getSectionIndex() == 0) {
            LOG(10, "relocation target for " << reloc->getAddress()
                << " points to an external module");
            return nullptr;
        }
        if(!weak && symbol->getBind() == Symbol::BIND_WEAK) {
            LOG(10, "weak symbol " << symbol->getName()
                << " should be resolved later");
            return nullptr;
        }
        if(symbol->isMarker()) {
            LOG(10, "making marker link " << reloc->getAddress()
                << " to " << addr);
            return module->getMarkerList()->createMarkerLink(
                symbol->getAddress(), reloc->getAddend(), symbol, module);
        }

        addr += symbol->getAddress();
    }
    LOG(10, "(resolveInternally) SEARCH for " << std::hex << addr);

    auto func = CIter::spatial(module->getFunctionList())->findContaining(addr);
    if(func) {
        if(func->getAddress() == addr) {
            LOG(10, "resolved to a function");
            return new NormalLink(func);
        }
        else {
            Chunk *inner = ChunkFind().findInnermostInsideInstruction(
                func, addr);
            auto instruction = dynamic_cast<Instruction *>(inner);
            LOG(10, "resolved to an instuction");
            return new NormalLink(instruction);
        }
    }

    if(auto dlink = LinkFactory::makeDataLink(module, addr, true)) {
        LOG(10, "resolved to a data");
        return dlink;
    }

    LOG(10, "resolved to a marker");
    return LinkFactory::makeMarkerLink(module, addr, nullptr);
}

Link *PerfectLinkResolver::resolveExternally(Symbol *symbol,
    Conductor *conductor, ElfSpace *elfSpace) {

    if(!symbol) return nullptr;

    const char *name = symbol->getName();
    LOG(10, "(resolveExternally) SEARCH for " << name);

    std::string versionedName;
    if(auto ver = symbol->getVersion()) {
        versionedName.append(name);
        versionedName.push_back('@');
        if(!ver->isHidden()) versionedName.push_back('@');
        versionedName.append(ver->getName());
    }

    // we cannot make a useful link to emulator symbol yet
    if(auto addr = LoaderEmulator::getInstance().findSymbol(name)) {
        LOG(10, "    symbol only link to emulator! at " << std::hex << addr);
        return new SymbolOnlyLink(symbol, addr);
    }

    for(auto library : *conductor->getLibraryList()) {
        auto space = library->getElfSpace();
        if(space && space != elfSpace) {
            if(auto link = resolveNameAsLinkHelper(name, space)) {
                return link;
            }
            else if(versionedName.size() > 0) {
                if(auto link = resolveNameAsLinkHelper(versionedName.c_str(),
                    space)) {

                    return link;
                }
            }
        }
    }

    // this should only happen for functions in a shared library which aren't
    // pulled in.
    LOG(9, "NOT FOUND: failed to make link to " << name);
    return nullptr;
}

Link *PerfectLinkResolver::resolveNameAsLinkHelper(const char *name,
    ElfSpace *space) {

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

    if(auto list = space->getSymbolList()) {
        if(auto symbol = list->find(name)) {
            if(symbol->isMarker()) {
                return LinkFactory::makeMarkerLink(space->getModule(),
                    space->getElfMap()->getBaseAddress() + symbol->getAddress(),
                    symbol);
            }
            if(symbol->getAddress() > 0
                && symbol->getType() != Symbol::TYPE_FUNC
                && symbol->getType() != Symbol::TYPE_IFUNC) {

                LOG(10, "    ...found as data ref! at "
                    << std::hex << symbol->getAddress() << " in "
                    << space->getModule()->getName());
                return LinkFactory::makeDataLink(space->getModule(),
                    symbol->getAddress(), true);
            }
        }
    }

    return nullptr;
}

Link *PerfectLinkResolver::resolveInferred(address_t address,
    Instruction *instruction, Module *module) {

    auto f = dynamic_cast<Function *>(
        instruction->getParent()->getParent());

    if(auto found = ChunkFind().findInnermostAt(f, address)) {
        LOG(10, " ==> inside the same function");
        return new NormalLink(found);
    }
    else if(auto found
        = CIter::spatial(module->getFunctionList())->find(address)) {

        LOG(10, " ==> " << found->getName());
        return new ExternalNormalLink(found);
    }
    else if(auto chunk = ChunkFind().findInnermostInsideInstruction(
        module->getFunctionList(), address)) {

        LOG(10, "--> instruction(literal?) " << chunk->getName());
        return new NormalLink(chunk);
    }
    else if(auto dlink = LinkFactory::makeDataLink(module, address, true)) {
        LOG(10, " --> data link");
        return dlink;
    }

    LOG(10, " --> marker link");
    return LinkFactory::makeMarkerLink(module, address, nullptr);;
}
