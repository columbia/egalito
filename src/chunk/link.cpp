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

ChunkRef PLTLink::getTarget() const {
    return pltTrampoline;
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

ChunkRef GSTableLink::getTarget() const {
    return entry->getTarget();
}

address_t GSTableLink::getTargetAddress() const {
    return entry->getOffset();
}

ChunkRef DistanceLink::getTarget() const {
    return target;
}

address_t DistanceLink::getTargetAddress() const {
    return target->getAddress() + target->getSize() - base->getAddress();
}

ChunkRef DataOffsetLink::getTarget() const {
    return section;
}

address_t DataOffsetLink::getTargetAddress() const {
    return section->getAddress() + target + addend;
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
    Conductor *conductor, ElfSpace *elfSpace, bool weak, bool afterMapping) {

    return resolveExternally2(symbol->getName(), symbol->getVersion(),
        conductor, elfSpace, weak, afterMapping);
}

Link *PerfectLinkResolver::resolveExternally(ExternalSymbol *externalSymbol,
    Conductor *conductor, ElfSpace *elfSpace, bool weak, bool afterMapping) {

    return resolveExternally2(externalSymbol->getName().c_str(),
        externalSymbol->getVersion(), conductor, elfSpace, weak,
        afterMapping);
}

Link *PerfectLinkResolver::resolveExternally2(const char *name,
    const SymbolVersion *version, Conductor *conductor, ElfSpace *elfSpace,
    bool weak, bool afterMapping) {

    LOG(10, "(resolveExternally) SEARCH for " << name << ", weak? " << weak);

    std::string versionedName;
    if(version) {
        versionedName.append(name);
        versionedName.push_back('@');
        if(!version->isHidden()) versionedName.push_back('@');
        versionedName.append(version->getName());
    }

    if(auto func = LoaderEmulator::getInstance().findFunction(name)) {
        LOG(10, "    link to emulated function!");
        return new ExternalNormalLink(func);
    }
    if(auto link = LoaderEmulator::getInstance().makeDataLink(name,
        afterMapping)) {

        LOG(10, "    link to emulated data!");
        return link;
    }

    auto dependencies = elfSpace->getModule()->getLibrary()->getDependencies();
    for(auto module : CIter::modules(conductor->getProgram())) {
        if(dependencies.find(module->getLibrary()) == dependencies.end()) {
            continue;
        }
        auto space = module->getElfSpace();
        if(space && space != elfSpace) {
            if(auto link = resolveNameAsLinkHelper(name, versionedName.c_str(),
                space, weak, afterMapping)) {

                return link;
            }
        }
    }

    // weak definition
    if(auto link = resolveNameAsLinkHelper(name, versionedName.c_str(), elfSpace,
        weak, afterMapping)) {

        LOG(10, "    link to weak definition in "
            << elfSpace->getModule()->getName());
        return link;
    }

    // weak reference
    for(auto module : CIter::modules(conductor->getProgram())) {
        auto space = module->getElfSpace();
        if(auto link = resolveNameAsLinkHelper(name, versionedName.c_str(),
            space, weak, afterMapping)) {

            LOG(10, "    link (weak) to definition in "
                << space->getModule()->getName());
            return link;
        }
    }

    // this should only happen for functions in a missing shared library
    LOG(9, "NOT FOUND: failed to make link to " << name);
    return nullptr;
}

Link *PerfectLinkResolver::resolveNameAsLinkHelper(const char *name,
    const char *versionedName, ElfSpace *space, bool weak, bool afterMapping) {

    if(auto link = resolveNameAsLinkHelper2(name, space, weak, afterMapping)) {
        return link;
    }
    if(!versionedName) return nullptr;
    return resolveNameAsLinkHelper2(versionedName, space, weak, afterMapping);
}

Link *PerfectLinkResolver::resolveNameAsLinkHelper2(const char *name,
    ElfSpace *space, bool weak, bool afterMapping) {

    Symbol *symbol = nullptr;
    auto list = space->getDynamicSymbolList();
    if(!list) {
        LOG(11, "no dynamic symbol list " << space->getModule()->getName());
        return nullptr;
    }
    symbol = list->find(name);
    if(!symbol) {
        LOG(11, "no symbol " << space->getModule()->getName());
        return nullptr;
    }
    if(!weak) {
        if(symbol->getBind() == Symbol::BIND_WEAK) return nullptr;
    }

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
        auto address = symbol->getAddress();
        if(afterMapping) {
            address += space->getElfMap()->getBaseAddress();
        }
        return LinkFactory::makeDataLink(space->getModule(),
            address, true);
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
