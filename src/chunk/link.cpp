#include <cassert>
#include "link.h"
#include "chunk/concrete.h"
#include "chunk/aliasmap.h"
#include "conductor/conductor.h"
#include "conductor/bridge.h"
#include "disasm/disassemble.h"
#include "elf/reloc.h"
#include "elf/elfspace.h"
#include "load/emulator.h"
#include "operation/find.h"
#include "operation/mutator.h"

#include "log/log.h"
#include "log/temp.h"
#include "chunk/dump.h"

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

address_t EgalitoLoaderLink::getTargetAddress() const {
    return LoaderBridge::getInstance()->getAddress(targetName);
}

address_t MarkerLink::getTargetAddress() const {
    return marker->getAddress();
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

    if(isRelative) {
        return new NormalLink(target, isExternal
            ? Link::SCOPE_EXTERNAL_JUMP : Link::SCOPE_INTERNAL_JUMP);
    }
    else {
        return new AbsoluteNormalLink(target, isExternal
            ? Link::SCOPE_EXTERNAL_JUMP : Link::SCOPE_INTERNAL_JUMP);
    }
}

Link *LinkFactory::makeDataLink(Module *module, address_t target,
    bool isRelative) {

    return module->getDataRegionList()->createDataLink(
        target, module, isRelative);
}

Link *LinkFactory::makeMarkerLink(Module *module, Symbol *symbol, size_t addend,
    bool isRelative) {

    return module->getMarkerList()->createMarkerLink(
        symbol, addend, module, isRelative);
}

Link *LinkFactory::makeInferredMarkerLink(Module *module, address_t address,
    bool isRelative) {

    return module->getMarkerList()->createInferredMarkerLink(
        address, module, isRelative);
}

#ifndef LINUX_KERNEL_MODE
static void appendNop(Function *function, size_t size) {
#ifdef ARCH_X86_64
    auto block = new Block();
    block->setPosition(PositionFactory::getInstance()
        ->makePosition(block, function->getSize()));

    DisasmHandle handle(true);
    Instruction *i = nullptr;
    switch(size) {
    case 1:
        i = DisassembleInstruction(handle).instruction(
            std::vector<unsigned char>({0x90}));
        break;
    case 2:
        i = DisassembleInstruction(handle).instruction(
            std::vector<unsigned char>({0x66, 0x90}));
        break;
    case 3:
        i = DisassembleInstruction(handle).instruction(
            std::vector<unsigned char>({0x0f, 0x1f, 0x00}));
        break;
    case 4:
        i = DisassembleInstruction(handle).instruction(
            std::vector<unsigned char>({0x0f, 0x1f, 0x40, 0x00}));
        break;
    case 5:
        i = DisassembleInstruction(handle).instruction(
            std::vector<unsigned char>({0x0f, 0x1f, 0x44, 0x00, 0x00}));
        break;
    case 6:
        i = DisassembleInstruction(handle).instruction(
            std::vector<unsigned char>({0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00}));
        break;
    case 7:
        i = DisassembleInstruction(handle).instruction(
            std::vector<unsigned char>(
                {0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00}));
        break;
    case 8:
        i = DisassembleInstruction(handle).instruction(
            std::vector<unsigned char>(
                {0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00}));
        break;
    case 9:
        i = DisassembleInstruction(handle).instruction(
            std::vector<unsigned char>(
                {0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00}));
        break;
    default:
        LOG(1, "NYI: appendNop for " << size);
        break;
    }
    assert(i);
    ChunkMutator(block).append(i);
    ChunkMutator(function).append(block);
#endif
}
#endif

static Function *getFunctionWithExpansion(address_t address, Module *module) {
    auto func = CIter::spatial(module->getFunctionList())
        ->findContaining(address);
    if(func) return func;

    if(auto region = module->getDataRegionList()
        ->findRegionContaining(address)) {

        if(region->executable()) {
            auto section = region->findDataSectionContaining(address);
            if(section && !section->isCode()) return nullptr;
        }
    }

#ifdef ARCH_AARCH64
    return nullptr;
#endif

    // for Linux, the problem of having the body of weak definition without
    // a symbol must be solved first
#ifndef LINUX_KERNEL_MODE
    // hack for functions aligned to 16B or less
    for(size_t i = 1; i < 16; i++) {
        func = CIter::spatial(module->getFunctionList())
            ->findContaining(address - i);
        if(func) {
            appendNop(func,
                address - (func->getAddress() + func->getSize() - 1));
            return func;
        }
    }
#endif

    return func;
}

Link *PerfectLinkResolver::resolveInternally(Reloc *reloc, Module *module,
    bool weak, bool relative) {

    auto i = ChunkFind().findInnermostInsideInstruction(
        module->getFunctionList(), reloc->getAddress());
    auto instr = dynamic_cast<Instruction *>(i);    // nullptr if from data

    address_t addend = reloc->getAddend();
    Symbol *symbol = reloc->getSymbol();
    address_t addr = addend;
    if(symbol) {
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
#if 0
        if(symbol->isMarker()) {
            LOG(10, "making marker link " << reloc->getAddress()
                << " to " << addr);
            return module->getMarkerList()->createMarkerLink(
                symbol, reloc->getAddend(), module, relative);
        }
#endif

#ifdef ARCH_X86_64
        auto type = reloc->getType();
        // R_X86_64_PC16 and R_X86_64_PC8 are not conformant to AMD64 ABI
        assert(type != R_X86_64_PC64
            && type != R_X86_64_GOTPCREL64
            && type != R_X86_64_GOTPC64
            && type != R_X86_64_PLTOFF64
            && type != R_X86_64_GOTPCREL
#ifdef R_X86_64_GOTPCRELX
            && type != R_X86_64_GOTPCRELX
#endif
#ifdef R_X86_64_REX_GOTPCRELX
            && type != R_X86_64_REX_GOTPCRELX
#endif
            && type != R_X86_64_PC16
            && type != R_X86_64_PC8);

        if(type == R_X86_64_PC32
            || type == R_X86_64_GOTPC32
        ) {
            if(!instr) {
                return nullptr; // maybe from .eh_frame?
            }
            // value should be S+A-P
            // => target should be S+A-(P - RIP@decode), where
            // -(P - RIP@decode) = RIP@decode - P = size - offset
            size_t offset = reloc->getAddress() - instr->getAddress();
            addr += symbol->getAddress() + instr->getSize() - offset;
        }
        else if(type == R_X86_64_GLOB_DAT) {
            // search first in the executable namespace for COPY
            auto program = dynamic_cast<Program *>(module->getParent());
            auto main = program->getMain();
            if(auto list = main->getElfSpace()->getSymbolList()) {
                auto s = list->find(symbol->getName());
                auto version = symbol->getVersion();
                if(!s && version) {
                    std::string versionedName(symbol->getName());
                    versionedName.push_back('@');
                    if(!version->isHidden()) versionedName.push_back('@');
                    versionedName.append(version->getName());
                    s = list->find(versionedName.c_str());
                    if(s) {
                        auto dlink = LinkFactory::makeDataLink(
                            main, s->getAddress(), relative);
                        LOG(1, "resolved to a data in module-(executable)");
                        return dlink;
                    }
                }
            }
            // value should be S
            addr = symbol->getAddress();
        }
        else {
            // value should be S+A
            addr += symbol->getAddress();
        }
#else
        addr += symbol->getAddress();
#endif
    }
    LOG(10, "(resolveInternally) SEARCH for " << std::hex << addr);

    auto func = getFunctionWithExpansion(addr, module);
    if(func) {
        bool external = !(instr && instr->getParent()->getParent() == func);
        if(func->getAddress() == addr) {
            LOG(10, "resolved to a function");
            return LinkFactory::makeNormalLink(func, relative, external);
        }
        else {
            Chunk *inner = ChunkFind().findInnermostInsideInstruction(
                func, addr);
            auto instruction = dynamic_cast<Instruction *>(inner);
            LOG(10, "resolved to an instuction");
            return LinkFactory::makeNormalLink(instruction, relative, external);
        }
    }

    if(auto dlink = LinkFactory::makeDataLink(module, addr, relative)) {
        LOG(10, "resolved to a data");
        return dlink;
    }

    if(auto mlink = LinkFactory::makeMarkerLink(module, symbol, addend,
        relative)) {

        LOG(10, "resolved to a marker, relative? " << relative);
        return mlink;
    }

    LOG(10, "UNRESOLVED");
    return nullptr;
}

Link *PerfectLinkResolver::resolveExternally(Symbol *symbol,
    Conductor *conductor, ElfSpace *elfSpace, bool weak, bool relative,
    bool afterMapping) {

    return resolveExternally2(symbol->getName(), symbol->getVersion(),
        conductor, elfSpace, weak, relative, afterMapping);
}

Link *PerfectLinkResolver::resolveExternally(ExternalSymbol *externalSymbol,
    Conductor *conductor, ElfSpace *elfSpace, bool weak, bool relative,
    bool afterMapping) {

    return resolveExternally2(externalSymbol->getName().c_str(),
        externalSymbol->getVersion(), conductor, elfSpace, weak,
        relative, afterMapping);
}

Link *PerfectLinkResolver::resolveExternally2(const char *name,
    const SymbolVersion *version, Conductor *conductor, ElfSpace *elfSpace,
    bool weak, bool relative, bool afterMapping) {

    LOG(10, "(resolveExternally) SEARCH for " << name << ", weak? " << weak);

    if(auto func = LoaderEmulator::getInstance().findFunction(name)) {
        LOG(10, "    link to emulated function!");
        return new NormalLink(func, Link::SCOPE_EXTERNAL_CODE);
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
            if(auto link = resolveNameAsLinkHelper(name, version,
                space, weak, relative, afterMapping)) {

                return link;
            }
        }
    }

    // weak definition
    if(auto link = resolveNameAsLinkHelper(name, version,
        elfSpace, weak, relative, afterMapping)) {

        LOG(10, "    link to weak definition in "
            << elfSpace->getModule()->getName());
        return link;
    }

    // weak reference
    for(auto module : CIter::modules(conductor->getProgram())) {
        auto space = module->getElfSpace();
        if(auto link = resolveNameAsLinkHelper(name, version,
            space, weak, relative, afterMapping)) {

            LOG(10, "    link (weak) to definition in "
                << space->getModule()->getName());
            return link;
        }
    }

    // this should only happen for functions in a missing shared library
    LOG(10, "NOT FOUND: failed to make link to " << name);
    return nullptr;
}

Link *PerfectLinkResolver::resolveNameAsLinkHelper(const char *name,
    const SymbolVersion *version,
    ElfSpace *space, bool weak, bool relative, bool afterMapping) {

    if(auto link = resolveNameAsLinkHelper2(
        name, space, weak, relative, afterMapping)) {

        return link;
    }
    // if there is a default versioned symbol, we need to make a link to
    // it, but this may not occur for gcc compiled binaries & libraries
    if(!version) return nullptr;

    std::string versionedName1(name);
    versionedName1.append("@");
    versionedName1.append(version->getName());
    if(auto link = resolveNameAsLinkHelper2(
        versionedName1.c_str(), space, weak, relative, afterMapping)) {

        return link;
    }
    std::string versionedName2(name);
    versionedName2.append("@@");
    versionedName1.append(version->getName());
    if(auto link = resolveNameAsLinkHelper2(
        versionedName2.c_str(), space, weak, relative, afterMapping)) {

        return link;
    }
    return nullptr;
}

Link *PerfectLinkResolver::resolveNameAsLinkHelper2(const char *name,
    ElfSpace *space, bool weak, bool relative, bool afterMapping) {

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
        return new NormalLink(f, Link::SCOPE_EXTERNAL_CODE);
    }

    auto alias = space->getAliasMap()->find(name);
    if(alias) {
        LOG(10, "    ...found as alias! " << alias->getName()
            << " at " << std::hex << alias->getAddress());
        return new NormalLink(alias, Link::SCOPE_EXTERNAL_CODE);
    }

    // resolving by name means that we are resolving to outside the module
    // and so no assumption can be made about the layout of other modules;
    // in other words, there should be no markers
#if 0
    if(symbol->isMarker()) {
        return LinkFactory::makeMarkerLink(space->getModule(),
            space->getElfMap()->getBaseAddress() + symbol->getAddress(),
            symbol, relative);
    }
#endif
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
    Instruction *instruction, Module *module, bool relative) {

    auto f = dynamic_cast<Function *>(
        instruction->getParent()->getParent());

    if(auto found = ChunkFind().findInnermostAt(f, address)) {
        LOG(10, " ==> inside the same function");
        return new NormalLink(found, Link::SCOPE_INTERNAL_JUMP);
    }
    else if(auto found
        = CIter::spatial(module->getFunctionList())->find(address)) {

        LOG(10, " ==> " << found->getName());
        return new NormalLink(found, Link::SCOPE_WITHIN_MODULE);
    }
    else if(auto chunk = ChunkFind().findInnermostInsideInstruction(
        module->getFunctionList(), address)) {

        LOG(10, "--> instruction(literal?) " << chunk->getName());
        return new NormalLink(chunk, Link::SCOPE_WITHIN_MODULE);
    }
    else if(auto dlink = LinkFactory::makeDataLink(module, address, true)) {
        LOG(10, " --> data link");
        return dlink;
    }

    LOG(10, " --> marker link");
    if(auto link = LinkFactory::makeInferredMarkerLink(module, address,
        relative)) {

        return link;
    }

    return nullptr;
}
