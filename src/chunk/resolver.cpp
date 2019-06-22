#include <cassert>
#include "resolver.h"
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

#ifndef LINUX_KERNEL_MODE
static void appendNop(Function *function, size_t size) {
#ifdef ARCH_X86_64
    auto block = new Block();
    auto prev = function->getChildren()->getIterable()->getLast();
    block->setPosition(PositionFactory::getInstance()
        ->makePosition(prev, block, function->getSize()));

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

Link *PerfectLinkResolver::redirectCopyRelocs(Conductor *conductor, Symbol *symbol,
    bool relative) {

    auto program = conductor->getProgram();
    auto main = program->getMain();
    if(main && main->getExeFile()) {
        /* relocations in every library, e.g. a PLT reloc for cerr in libstdc++,
         * should point at the executable's copy of the global if COPY reloc is present
         */
        if(auto symList = main->getExeFile()->getSymbolList()) {
            if(auto ret = redirectCopyRelocs(main, symbol, symList, relative)) {
                return ret;
            }
        }
        if(auto dynList = main->getExeFile()->getDynamicSymbolList()) {
            if(auto ret = redirectCopyRelocs(main, symbol, dynList, relative)) {
                return ret;
            }
        }
    }
    return nullptr;
}

Link *PerfectLinkResolver::redirectCopyRelocs(Conductor *conductor, ExternalSymbol *symbol,
    bool relative) {

    auto program = conductor->getProgram();
    auto main = program->getMain();
    if(main && main->getExeFile()) {
        /* relocations in every library, e.g. a PLT reloc for cerr in libstdc++,
         * should point at the executable's copy of the global if COPY reloc is present
         */
        if(auto symList = main->getExeFile()->getSymbolList()) {
            if(auto ret = redirectCopyRelocs(main, symbol, symList, relative)) {
                return ret;
            }
        }
        if(auto dynList = main->getExeFile()->getDynamicSymbolList()) {
            if(auto ret = redirectCopyRelocs(main, symbol, dynList, relative)) {
                return ret;
            }
        }
    }
    return nullptr;
}

Link *PerfectLinkResolver::redirectCopyRelocs(Module *main, Symbol *symbol,
    SymbolList *list, bool relative) {

    LOG(1, "redirect copy relocs [" << symbol->getName() << "]");

    auto s = list->find(symbol->getName());
    auto version = symbol->getVersion();
    if(!s && version) {
        std::string versionedName(symbol->getName());
        versionedName.push_back('@');
        versionedName.append(version->getName());
        s = list->find(versionedName.c_str());
        if(!s) {
            std::string versionedName(symbol->getName());
            versionedName.append("@@");
            versionedName.append(version->getName());
            s = list->find(versionedName.c_str());
        }
    }
    if(s) {
        auto dlink = LinkFactory::makeDataLink(
            main, main->getBaseAddress() + s->getAddress(), relative);
        LOG(1, "    COPY resolved to data in module-(executable): "
            <<  s->getAddress());
        return dlink;
    }
    return nullptr;
}

Link *PerfectLinkResolver::redirectCopyRelocs(Module *main,
    ExternalSymbol *extSym, SymbolList *list, bool relative) {

    LOG(1, "redirect copy relocs [" << extSym->getName() << "]");

    auto s = list->find(extSym->getName().c_str());
    auto version = extSym->getVersion();
    if(!s && version) {
        std::string versionedName(extSym->getName());
        versionedName.push_back('@');
        versionedName.append(version->getName());
        s = list->find(versionedName.c_str());
        if(!s) {
            std::string versionedName(extSym->getName());
            versionedName.append("@@");
            versionedName.append(version->getName());
            s = list->find(versionedName.c_str());
        }
    }
    if(s) {
        auto dlink = LinkFactory::makeDataLink(
            main, main->getBaseAddress() + s->getAddress(), relative);
        LOG(1, "resolved to data in module-(executable): "
            <<  s->getAddress());
        return dlink;
    }
    return nullptr;
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
            LOG(1, "Handling glob_dat relocation at 0x"
                        << std::hex << reloc->getAddress());
            auto program = dynamic_cast<Program *>(module->getParent());
            auto main = program->getMain();
            if(main) {
                /* relocations in every library, e.g. a PLT reloc for cerr in libstdc++,
                 * should point at the executable's copy of the global if COPY reloc is present
                 */
                if(auto symList = main->getExeFile()->getSymbolList()) {
                    if(auto ret = redirectCopyRelocs(main, symbol, symList, relative)) {
                        return ret;
                    }
                }
                if(auto dynList = main->getExeFile()->getDynamicSymbolList()) {
                    if(auto ret = redirectCopyRelocs(main, symbol, dynList, relative)) {
                        return ret;
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

Link *PerfectLinkResolver::resolveExternallyStrongWeak(Symbol *symbol,
    Conductor *conductor, Module *module, bool relative,
    bool afterMapping) {

    auto l = resolveExternallyHelper(symbol->getName(), symbol->getVersion(),
        conductor, module, /*weak=*/ false, relative, afterMapping);
    if(!l) {
        l = resolveExternallyHelper(symbol->getName(), symbol->getVersion(),
            conductor, module, /*weak=*/ true, relative, afterMapping);
    }
    return l;
}

Link *PerfectLinkResolver::resolveExternallyStrongWeak(ExternalSymbol *externalSymbol,
    Conductor *conductor, Module *module, bool relative,
    bool afterMapping) {

    auto l = resolveExternallyHelper(externalSymbol->getName().c_str(),
        externalSymbol->getVersion(), conductor, module, /*weak=*/ false,
        relative, afterMapping);
    if(!l) {
        l = resolveExternallyHelper(externalSymbol->getName().c_str(),
            externalSymbol->getVersion(), conductor, module, /*weak=*/ true,
            relative, afterMapping);
    }
    return l;
}

Link *PerfectLinkResolver::resolveExternally(Symbol *symbol,
    Conductor *conductor, Module *module, bool weak, bool relative,
    bool afterMapping) {

    return resolveExternallyHelper(symbol->getName(), symbol->getVersion(),
        conductor, module, weak, relative, afterMapping);
}

Link *PerfectLinkResolver::resolveExternally(ExternalSymbol *externalSymbol,
    Conductor *conductor, Module *module, bool weak, bool relative,
    bool afterMapping) {

    return resolveExternallyHelper(externalSymbol->getName().c_str(),
        externalSymbol->getVersion(), conductor, module, weak,
        relative, afterMapping);
}

Link *PerfectLinkResolver::resolveExternallyHelper(const char *name,
    const SymbolVersion *version, Conductor *conductor, Module *module,
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

    auto dependencies = module->getLibrary()->getDependencies();
    for(auto m : CIter::modules(conductor->getProgram())) {
        if(dependencies.find(m->getLibrary()) == dependencies.end()) {
            continue;
        }
        
        if(m != module) {
            if(auto link = resolveNameAsLinkHelper(name, version,
                m, weak, relative, afterMapping)) {

                return link;
            }
        }
    }

    // were we asked to look at weak symbols?
    if(!weak) {
        LOG(11, "Didn't find strong " << name
            << " externally, not looking for weak version");
        return nullptr;
    }

    // weak definition
    if(auto link = resolveNameAsLinkHelper(name, version,
        module, weak, relative, afterMapping)) {

        LOG(10, "    link to weak definition in " << module->getName());
        return link;
    }

    // weak reference
    for(auto m : CIter::modules(conductor->getProgram())) {
        if(auto link = resolveNameAsLinkHelper(name, version,
            m, weak, relative, afterMapping)) {

            LOG(10, "    link (weak) to definition in " << m->getName());
            return link;
        }
    }

    // this should only happen for functions in a missing shared library
    LOG(10, "NOT FOUND: failed to make link to " << name);
    return nullptr;
}

Link *PerfectLinkResolver::resolveNameAsLinkHelper(const char *name,
    const SymbolVersion *version,
    Module *module, bool weak, bool relative, bool afterMapping) {

    LOG(1, "        resolveNameAsLinkHelper (" << name << ") inside "
        << module->getName());

    if(auto link = resolveNameAsLinkHelper2(
        name, module, weak, relative, afterMapping)) {

        return link;
    }
    // if there is a default versioned symbol, we need to make a link to
    // it, but this may not occur for gcc compiled binaries & libraries
    if(!version) return nullptr;

    std::string versionedName1(name);
    versionedName1.append("@");
    versionedName1.append(version->getName());
    if(auto link = resolveNameAsLinkHelper2(
        versionedName1.c_str(), module, weak, relative, afterMapping)) {

        return link;
    }
    std::string versionedName2(name);
    versionedName2.append("@@");
    versionedName2.append(version->getName());
    if(auto link = resolveNameAsLinkHelper2(
        versionedName2.c_str(), module, weak, relative, afterMapping)) {

        return link;
    }
    return nullptr;
}

Link *PerfectLinkResolver::resolveNameAsLinkHelper2(const char *name,
    Module *module, bool weak, bool relative, bool afterMapping) {

    Symbol *symbol = nullptr;
    auto list = module->getExeFile()->getDynamicSymbolList();
    if(!list) {
        LOG(11, "no dynamic symbol list " << module->getName());
        return nullptr;
    }
    symbol = list->find(name);
    if(!symbol) {
        LOG(11, "no symbol " << module->getName());
        return nullptr;
    }

    // early out if we are not searching for weak symbols
    if(!weak && symbol->getBind() == Symbol::BIND_WEAK) return nullptr;

    auto f = CIter::named(module->getFunctionList())->find(name);
    if(f) {
        LOG(10, "    ...found as function! at "
            << std::hex << f->getAddress());
        return new NormalLink(f, Link::SCOPE_EXTERNAL_CODE);
    }

    if(auto elfFile = module->getExeFile()->asElf()) {
        auto alias = elfFile->getAliasMap()->find(name);
        if(alias) {
            LOG(10, "    ...found as alias! " << alias->getName()
                << " at " << std::hex << alias->getAddress());
            return new NormalLink(alias, Link::SCOPE_EXTERNAL_CODE);
        }
    }

    // resolving by name means that we are resolving to outside the module
    // and so no assumption can be made about the layout of other modules;
    // in other words, there should be no markers
#if 0
    if(symbol->isMarker()) {
        return LinkFactory::makeMarkerLink(module,
            module->getExeFile()->getMap()->getBaseAddress() + symbol->getAddress(),
            symbol, relative);
    }
#endif
    if(symbol->getAddress() > 0
        && symbol->getType() != Symbol::TYPE_FUNC
        && symbol->getType() != Symbol::TYPE_IFUNC) {

        LOG(10, "    ...found as data ref! at "
            << std::hex << symbol->getAddress() << " in "
            << module->getName());
        auto address = symbol->getAddress();
        if(afterMapping) {
            address += module->getBaseAddress();
        }
        if(address == 0x399204) {
            LOG(1, "    special case");
        }
        auto t = LinkFactory::makeDataLink(module, address, true);

        LOG(1, "    address 0x" << std::hex << address << " -> " << t);
//        return LinkFactory::makeDataLink(module, address, true);
          return t;
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
