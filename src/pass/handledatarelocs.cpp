#include <typeinfo>
#include <cstring>
#include <cassert>
#include "handledatarelocs.h"
#include "chunk/link.h"
#include "chunk/external.h"
#include "operation/mutator.h"
#include "elf/elfspace.h"
#include "elf/reloc.h"
#include "log/log.h"
#include "log/temp.h"

void HandleDataRelocsPass::visit(Module *module) {
    //TemporaryLogLevel tl1("chunk", 10, module->getName() == "module-(executable)");
    TemporaryLogLevel tl1("chunk", 10);
    TemporaryLogLevel tl2("pass", 15);

    assert(module->getElfSpace() != nullptr);
    auto elfMap = module->getElfSpace()->getElfMap();

    // make DataVariables for every relocation in every ElfSection
    for(ElfSection *section : elfMap->getSectionList()) {
        auto relocSection = module->getElfSpace()->getRelocList()->getSection(
            section->getName());
        if(!relocSection) continue;  // no relocs in this ElfSection

        if(auto info = relocSection->getInfoLink()) {
            auto sourceSection = elfMap->findSection(info);
            if(sourceSection->getName() == "__kcrctab") continue;
            if(sourceSection->getName() == ".rela__kcrctab") continue;
            if(sourceSection->getName() == "__kcrctab_gpl") continue;
            if(sourceSection->getName() == ".rela__kcrctab_gpl") continue;

            if(sourceSection->getName() == ".data..percpu") continue;
            if(sourceSection->getName() == ".rela.data..percpu") continue;

            // skip relocations for instructions
            auto shdr = sourceSection->getHeader();
            if(shdr->sh_flags & SHF_EXECINSTR) continue;

            resolveSpecificRelocSection(relocSection, module);
        }
        else {
            resolveGeneralRelocSection(relocSection, module);
        }
    }
}

// This pass is run multiple times, so we must check the existence first
// otherwise we leak the link
void HandleDataRelocsPass::resolveSpecificRelocSection(
    RelocSection *relocSection, Module *module) {

    auto addr = (*relocSection->begin())->getAddress() + module->getBaseAddress();
    auto region = module->getDataRegionList()->findRegionContaining(addr);
    auto section = region->findDataSectionContaining(addr);

    for(auto reloc : *relocSection) {
        auto a = reloc->getAddress() + module->getBaseAddress();
        if(section->findVariable(a)) continue;

        auto link = resolveVariableLink(reloc, module);
        // always create a DataVariable, even if the link is null

        DataVariable::create(section, a, link, reloc->getSymbol());
    }
}

void HandleDataRelocsPass::resolveGeneralRelocSection(
    RelocSection *relocSection, Module *module) {

    auto list = module->getDataRegionList();
    for(auto reloc : *relocSection) {
        auto addr = reloc->getAddress() + module->getBaseAddress();
        auto region = list->findRegionContaining(addr);
        auto section = region->findDataSectionContaining(addr);
        if(section->findVariable(addr)) continue;

        LOG(10, "trying to resolve reloc at " << std::hex << addr);
        auto link = resolveVariableLink(reloc, module);
        // always create a DataVariable, even if the link is null

        DataVariable::create(module, addr, link, reloc->getSymbol());
    }
}

Link *HandleDataRelocsPass::resolveVariableLink(Reloc *reloc, Module *module) {

    Symbol *symbol = reloc->getSymbol();

#ifdef ARCH_X86_64
    if(reloc->getType() == R_X86_64_NONE) {
        return nullptr;
    }
    else if(reloc->getType() == R_X86_64_RELATIVE) {
        auto l =  PerfectLinkResolver().resolveInternally(reloc, module, weak);
        LOG(0, "reloc relative at 0x" << std::hex << reloc->getAddress() 
            << ", link = " << std::hex << l);
        return l;
    }
    else if(reloc->getType() == R_X86_64_IRELATIVE) {
        return PerfectLinkResolver().resolveInternally(reloc, module, weak);
    }
    else if(reloc->getType() == R_X86_64_TPOFF64) {
        auto tls = module->getDataRegionList()->getTLS();
        if(symbol && symbol->getSectionIndex() == SHN_UNDEF) {
            tls = nullptr;
        }
        return new TLSDataOffsetLink(
            tls, reloc->getSymbol(), reloc->getAddend());
    }
    else if(reloc->getType() == R_X86_64_DTPMOD64) {
        LOG(0, "WARNING: skipping R_X86_64_DTPMOD64 ("
            << std::hex << reloc->getAddress()
            << ") in " << module->getName());
        return nullptr;
    }
    else if(reloc->getType() == R_X86_64_COPY) {
        LOG(10, "WARNING: skipping R_X86_64_COPY ("
            << std::hex << reloc->getAddress()
            << ") in " << module->getName());
        return nullptr;
    }
    else if(reloc->getType() == R_X86_64_GLOB_DAT) {
        if(!internal) {
            LOG(0, "processing R_X86_64_GLOB_DAT ("
                << std::hex << reloc->getAddress()
                << ") in " << module->getName());
            auto l = PerfectLinkResolver().resolveExternally(
                reloc->getSymbol(), conductor, module->getElfSpace(), weak, false, true);
            if(!l) {
                l = PerfectLinkResolver().resolveInternally(reloc, module, weak, false);
            }
            #if 0 // moved to later pass
            if(false && !l) {
                auto externalSymbol = ExternalSymbolFactory(module)
                    .makeExternalSymbol(reloc->getSymbol());
                l = new ExternalSymbolLink(externalSymbol);
            }
            #endif

            LOG(0, "link is " << l);
            return l;
        }
        else {
            LOG(0, "checking GLOB_DAT relocation ["
                << reloc->getSymbol()->getName() << "] for internal link");
            auto l = PerfectLinkResolver().resolveInternally(reloc, module, weak, false);
            if(auto v = dynamic_cast<AbsoluteDataLink *>(l)) {
                auto externalSymbol = ExternalSymbolFactory(module)
                    .makeExternalSymbol(reloc->getSymbol());
                auto newLink = new InternalAndExternalDataLink(externalSymbol, v);
                delete v;
                return newLink;
            }
            return nullptr;
        }
    }
    else if(reloc->getType() == R_X86_64_64) {
        // want a non-relative lookup
        auto l =  PerfectLinkResolver().resolveInternally(reloc, module, weak, false);
        LOG(0, "reloc 64_64 at 0x" << std::hex << reloc->getAddress() 
            << ", link = " << std::hex << l);
        if(auto abs = dynamic_cast<AbsoluteDataLink *>(l)) {
            LOG(0, "    absolute DOL: " << abs->getTargetAddress());
        }
        else if(auto rel = dynamic_cast<DataOffsetLink *>(l)) {
            LOG(0, "    relative DOL: " << rel->getTargetAddress());
        }
        else LOG(0, "??!?");
        return l;
        
    }
#else
    // We can't resolve the address yet, because a link may point to a TLS
    // in another module e.g. errno referred from libm (tls can be nullptr)
#if defined(R_AARCH64_TLS_TPREL64) && !defined(R_AARCH64_TLS_TPREL)
    #define R_AARCH64_TLS_TPREL R_AARCH64_TLS_TPREL64
#endif
    if(reloc->getType() == R_AARCH64_TLS_TPREL
        || reloc->getType() == R_AARCH64_TLSDESC) {

        auto tls = module->getDataRegionList()->getTLS();
        if(symbol && symbol->getSectionIndex() == SHN_UNDEF) {
            tls = nullptr;
        }
        return new TLSDataOffsetLink(
            tls, reloc->getSymbol(), reloc->getAddend());
    }
#endif

#ifdef R_RISCV_TLS_TPREL64
    if(reloc->getType() == R_RISCV_TLS_TPREL64) {
        LOG(1, "dealing with TPREL64 relocation...");
        auto tls = module->getDataRegionList()->getTLS();
        if(symbol && symbol->getSectionIndex() == SHN_UNDEF) {
            tls = nullptr;
        }
        return new TLSDataOffsetLink(
            tls, reloc->getSymbol(), reloc->getAddend());
    }
#endif

    if(internal) {
        return PerfectLinkResolver().resolveInternally(reloc, module, weak);
    }
    assert(symbol);
    if(std::strcmp(symbol->getName(), "") != 0) {
        if(weak || symbol->getBind() != Symbol::BIND_WEAK) {
            auto link = PerfectLinkResolver().resolveExternally(
                symbol, conductor, module->getElfSpace(), weak, false);
            if(link && reloc->getAddend() > 0) {
                if(auto dlink = dynamic_cast<DataOffsetLink *>(link)) {
                    dlink->setAddend(reloc->getAddend());
                }
                else {
                    throw "resolveVariableLink: unexpected addend > 0";
                }
            }
            return link;
        }
    }
    return nullptr;
}
