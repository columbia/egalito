#include <cstring>
#include <cassert>
#include "handledatarelocs.h"
#include "chunk/link.h"
#include "elf/elfspace.h"
#include "elf/reloc.h"
#include "log/log.h"

void HandleDataRelocsPass::visit(Module *module) {
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

            LOG(10, "sourceRegion is " << sourceRegion->getName());
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
                sourceRegion->addVariable(var);
            }
        }
    }
}

Link *HandleDataRelocsPass::resolveVariableLink(Reloc *reloc, Module *module) {
#ifdef ARCH_X86_64
    // this is the only reloc type we've seen in TLS
    if(reloc->getType() == R_X86_64_RELATIVE) {
        return PerfectLinkResolver().resolveInternally(reloc, module, weak);
    }
    return nullptr;
#else
    // We can't resolve the address yet, because a link may point to a TLS
    // in another module e.g. errno referred from libm (tls can be nullptr)
#if defined(R_AARCH64_TLS_TPREL64) && !defined(R_AARCH64_TLS_TPREL)
    #define R_AARCH64_TLS_TPREL R_AARCH64_TLS_TPREL64
#endif
    Symbol *symbol = reloc->getSymbol();

    if(reloc->getType() == R_AARCH64_TLS_TPREL
        || reloc->getType() == R_AARCH64_TLSDESC) {

        auto tls = module->getDataRegionList()->getTLS();
        if(symbol && symbol->getSectionIndex() == SHN_UNDEF) {
            tls = nullptr;
        }
        return new TLSDataOffsetLink(
            tls, reloc->getSymbol(), reloc->getAddend());
    }

    if(internal) {
        return PerfectLinkResolver().resolveInternally(reloc, module, weak);
    }
    assert(symbol);
    if(std::strcmp(symbol->getName(), "") != 0) {
        if(weak || symbol->getBind() != Symbol::BIND_WEAK) {
            if(reloc->getAddend() > 0) {
                auto addr = symbol->getAddress() + reloc->getAddend();
                auto symbolList = module->getElfSpace()->getSymbolList();
                if(symbolList) {
                    if(auto s = symbolList->find(addr)) {
                        symbol = s;
                    }
                }
            }
            return PerfectLinkResolver().resolveExternally(symbol, conductor,
                module->getElfSpace());
        }
    }
    return nullptr;
#endif
}
