#include <typeinfo>
#include "resolveexternallinks.h"
#include "chunk/link.h"
#include "conductor/conductor.h"
#include "elf/elfspace.h"
#include "log/log.h"

void ResolveExternalLinksPass::visit(Module *module) {
    for(auto dr : CIter::regions(module)) {
        for(auto ds : CIter::children(dr)) {
            for(auto dv : CIter::children(ds)) {
                auto link = dv->getDest();
                if(!link && dv->getTargetSymbol()) {
                    auto symbol = dv->getTargetSymbol();
                    auto l = PerfectLinkResolver().resolveExternally(
                        symbol, conductor, module->getElfSpace(), false, false, true);
                    if(!l) {
                        l = PerfectLinkResolver().resolveExternally(
                            symbol, conductor, module->getElfSpace(), true, false, true);
                    }
                    if(!dv->getIsCopy()) {
                        if(l) LOG(0, "change null link from ["
                            << symbol->getName() << "] => " << l << ", " << typeid(*l).name());
                        dv->setDest(l);
                    }
                    else {
                        //auto link = new CopyRelocLink(externalSymbol);
                        //dv->setDest(link);
                    }
                }
                else if(auto v = dynamic_cast<InternalAndExternalDataLink *>(link)) {
#if 0
                    /*if(!dv->getIsCopy()) {
                        auto extSym = v->getExternalSymbol();
                        auto l = PerfectLinkResolver().resolveExternally(
                            extSym, conductor, module->getElfSpace(), false, false, true);
                        if(!l) {
                            l = PerfectLinkResolver().resolveExternally(
                                extSym, conductor, module->getElfSpace(), true, false, true);
                        }
                        LOG(0, "change InternalAndExternalDataLink from ["
                            << extSym->getName() << "] => " << l << " (" << std::hex << l->getTargetAddress() << ")");
                        dv->setDest(l);
                        delete link;
                    }
                    else */{
                        auto extSym = v->getExternalSymbol();
                        auto main = conductor->getProgram()->getMain();
                        if(main) {
                            // Cloned from link.cpp
                            /* relocations in every library, e.g. a PLT reloc for cerr in libstdc++,
                             * should point at the executable's copy of the global if COPY reloc is present
                             */
                            if(auto symList = main->getElfSpace()->getSymbolList()) {
                                if(auto l = PerfectLinkResolver().redirectCopyRelocs(main, extSym, symList, false)) {
                                    LOG(0, "change InternalAndExternalDataLink COPY from ["
                                        << extSym->getName() << "] => " << l << " (" << std::hex << l->getTargetAddress() << ")");
                                    dv->setDest(l);
                                    delete link;
                                }
                            }
                            if(auto dynList = main->getElfSpace()->getDynamicSymbolList()) {
                                if(auto l = PerfectLinkResolver().redirectCopyRelocs(main, extSym, dynList, false)) {
                                    LOG(0, "change InternalAndExternalDataLink COPY from ["
                                        << extSym->getName() << "] => " << l << " (" << std::hex << l->getTargetAddress() << ")");
                                    dv->setDest(l);
                                    delete link;
                                }
                            }
                        }
                    }
#endif

                }
                else if(auto v = dynamic_cast<ExternalSymbolLink *>(link)) {
                    auto extSym = v->getExternalSymbol();
#if 0
                    auto l = PerfectLinkResolver().resolveExternally(
                        extSym, conductor, module->getElfSpace(), false, false, true);
                    if(!l) {
                        l = PerfectLinkResolver().resolveExternally(
                            extSym, conductor, module->getElfSpace(), true, false, true);
                    }
                    dv->setDest(l);
                    delete link;
#else
                    LOG(0, "WARNING: Unresolved ExternalSymbolLink to ["
                        << extSym->getName());
#endif
                }
            }
        }
    }
}
