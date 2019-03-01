#include "resolveexternallinks.h"
#include "chunk/link.h"
#include "conductor/conductor.h"
#include "elf/elfspace.h"
#include "log/log.h"

template <typename SymbolType>
static Link *reResolveTarget(SymbolType *symbol, Conductor *conductor, Module *module) {
    auto l = PerfectLinkResolver().resolveExternally(
        symbol, conductor, module->getElfSpace(), /*weak=*/ false, false, true);
    if(!l) {
        l = PerfectLinkResolver().resolveExternally(
            symbol, conductor, module->getElfSpace(), /*weak=*/ true, false, true);
    }
    return l;
}

void ResolveExternalLinksPass::visit(Module *module) {
    for(auto dr : CIter::regions(module)) {
        for(auto ds : CIter::children(dr)) {
            for(auto dv : CIter::children(ds)) {
                auto link = dv->getDest();
                if(!link && dv->getTargetSymbol()) {
#if 1
                    auto symbol = dv->getTargetSymbol();
                    auto l = reResolveTarget(symbol, conductor, module);
                    if(l) {
                        LOG(0, "change null link in " << module->getName() << " from ["
                            << symbol->getName() << "] => " << l << " (" << std::hex << l->getTargetAddress() << ")");
                        dv->setDest(l);
                    }
#else
                    auto symbol = dv->getTargetSymbol();
                    auto main = conductor->getProgram()->getMain();
                    if(main) {
                        // Cloned from link.cpp
                        /* relocations in every library, e.g. a PLT reloc for cerr in libstdc++,
                         * should point at the executable's copy of the global if COPY reloc is present
                         */
                        if(auto symList = main->getElfSpace()->getSymbolList()) {
                            if(auto l = PerfectLinkResolver().redirectCopyRelocs(main, symbol, symList, false)) {
                                LOG(0, "change InternalAndExternalDataLink COPY from ["
                                    << symbol->getName() << "] => " << l << " (" << std::hex << l->getTargetAddress() << ")");
                                dv->setDest(l);
                                delete link;
                            }
                        }
                        if(auto dynList = main->getElfSpace()->getDynamicSymbolList()) {
                            if(auto l = PerfectLinkResolver().redirectCopyRelocs(main, symbol, dynList, false)) {
                                LOG(0, "change InternalAndExternalDataLink COPY from ["
                                    << symbol->getName() << "] => " << l << " (" << std::hex << l->getTargetAddress() << ")");
                                dv->setDest(l);
                                delete link;
                            }
                        }
                    }
#endif
                }
                else if(auto v = dynamic_cast<InternalAndExternalDataLink *>(link)) {
                    if(!dv->getIsCopy()) {
                        auto extSym = v->getExternalSymbol();
                        auto l = reResolveTarget(extSym, conductor, module);
                        if(l) {
                            LOG(0, "change InternalAndExternalDataLink in " << module->getName() << " from ["
                                << extSym->getName() << "] => " << l << " (" << std::hex << l->getTargetAddress() << ")");
                            dv->setDest(l);
                            delete link;
                        }
                    }
                }
                else if(auto v = dynamic_cast<ExternalSymbolLink *>(link)) {
                    auto extSym = v->getExternalSymbol();
                    auto l = reResolveTarget(extSym, conductor, module);
                    if(l) {
                        LOG(0, "change ExternalSymbolLink from ["
                            << extSym->getName() << "] => " << l << " (" << std::hex << l->getTargetAddress() << ")");
                        dv->setDest(l);
                        delete link;
                    }
                }
            }
        }
    }
}
