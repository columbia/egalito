#include <cstring>
#include <cassert>
#include "handledatarelocs.h"
#include "chunk/link.h"
#include "elf/elfspace.h"
#include "elf/reloc.h"
#include "log/log.h"
#include "log/temp.h"

void HandleDataRelocsPass::visit(Module *module) {
    //TemporaryLogLevel tll("pass", 10, module->getName() == "module-(executable)");
    auto list = module->getDataRegionList();

    // make variables for all relocations located inside the regions
    for(auto reloc : *relocList) {
        // source region (will be different from the link's dest region)
        auto sourceRegion = list->findRegionContaining(reloc->getAddress());
        if(sourceRegion) {
            auto sourceSection
                = sourceRegion->findDataSectionContaining(reloc->getAddress());
            if(!sourceSection) continue;
            if(sourceSection->isCode()) {
                // it's useless to make a link from code to literal here
                // because we won't be able to reach it after remap
                continue;
            }

            if(sourceRegion->findVariable(reloc->getAddress())) continue;

            LOG(11, "sourceRegion is " << sourceRegion->getName());
            if(auto link = resolveVariableLink(reloc, module)) {
                auto addr = reloc->getAddress();
                LOG0(10, "resolving a variable at " << std::hex << addr);
                if(auto sym = reloc->getSymbol()) {
                    LOG(10, " => " << sym->getName()
                        << " + " << reloc->getAddend());
                }
                else LOG(10, " => " << reloc->getAddend());
                if(sourceRegion == list->getTLS()) LOG(11, "from TLS!");
                auto var = new DataVariable(sourceRegion, addr, link);
                if(reloc->getSymbol()) {
                    var->setName(reloc->getSymbol()->getName());
                }
                sourceRegion->addVariable(var);
            }
        }
    }
}

Link *HandleDataRelocsPass::resolveVariableLink(Reloc *reloc, Module *module) {
    //TemporaryLogLevel tll("chunk", 10, module->getName() == "module-libc.so.6");

    Symbol *symbol = reloc->getSymbol();

#ifdef ARCH_X86_64
    if(reloc->getType() == R_X86_64_NONE) {
        return nullptr;
    }
    if(reloc->getType() == R_X86_64_RELATIVE) {
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
    if(reloc->getType() == R_X86_64_COPY) {
        LOG(0, "WARNING: skipping R_X86_64_COPY ("
            << std::hex << reloc->getAddress()
            << ") in " << module->getName());
        return nullptr;
    }
#if 0
    if(reloc->getType() == R_X86_64_PC32
        || reloc->getType() == R_X86_64_PC16
        || reloc->getType() == R_X86_64_PC8
        || reloc->getType() == R_X86_64_PC64) {

        // creating a variable for these requires instruction address
        LOG(9, "WARNING: skipping PC-relative relocations");
        return nullptr;
    }
#endif
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

    if(internal) {
        return PerfectLinkResolver().resolveInternally(reloc, module, weak);
    }
    assert(symbol);
    if(std::strcmp(symbol->getName(), "") != 0) {
        if(weak || symbol->getBind() != Symbol::BIND_WEAK) {
            auto link = PerfectLinkResolver().resolveExternally(
                symbol, conductor, module->getElfSpace());
            if(reloc->getAddend() > 0) {
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
