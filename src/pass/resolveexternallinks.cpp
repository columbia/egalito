#include "resolveexternallinks.h"
#include "chunk/resolver.h"
#include "conductor/conductor.h"
#include "elf/elfspace.h"
#include "log/log.h"

template <typename SymbolType>
static Link *reResolveTarget(SymbolType *symbol, Conductor *conductor, Module *module) {
    // note: only called on datavariable links
    auto l = PerfectLinkResolver().redirectCopyRelocs(conductor, symbol, false);
    if(l) {
        LOG(1, "IT'S A COPY!");
    }
    if(!l) {
        l = PerfectLinkResolver().resolveExternally(symbol, conductor,
            module, false, true, /*afterMapping=*/ true);
        if(!l) {
            l = PerfectLinkResolver().resolveExternally(symbol, conductor,
                module, true, true, /*afterMapping=*/ true);
        }
    }
    return l;
}

static Link *reResolveTarget(ExternalSymbol *symbol, Conductor *conductor, Module *module, int addend) {
    // note: only called on datavariable links
    auto l = PerfectLinkResolver().redirectCopyRelocs(conductor, symbol, false);
    if(l) {
        LOG(1, "IT'S A COPY!");
    }
    if(!l) {
        l = PerfectLinkResolver().resolveExternally(symbol, conductor,
            module, addend, false, true, /*afterMapping=*/ true);
        if(!l) {
            l = PerfectLinkResolver().resolveExternally(symbol, conductor,
                module, addend, true, true, /*afterMapping=*/ true);
        }
    }
    return l;
}

void ResolveExternalLinksPass::visit(Module *module) {
    for(auto dr : CIter::regions(module)) {
        for(auto ds : CIter::children(dr)) {
            for(auto dv : CIter::children(ds)) {
                if((dv->getAddress() & 0xffffff) == 0x1777a8) {
                    LOG(0, "Found interesting point");
                }
                auto link = dv->getDest();
                if(!link && dv->getTargetSymbol()) {
                    auto symbol = dv->getTargetSymbol();
                    auto l = reResolveTarget(symbol, conductor, module);
                    if(l) {
                        LOG(0, "change null link in " << module->getName() << " from ["
                            << symbol->getName() << "] => " << l << " (0x"
                            << std::hex << l->getTargetAddress() << ")");
                        dv->setDest(l);
                    }
                }
                else if(auto v = dynamic_cast<CopyRelocLink *>(link)) {
                    /*auto extSym = v->getExternalSymbol();
                    if(!extSym->getResolved()) {
                        auto l = reResolveTarget(extSym, conductor, module);
                        if(l) {
                            LOG(0, "change CopyRelocLink in " << module->getName()
                                << " from [" << extSym->getName() << "] => " << l << " (0x"
                                << std::hex << l->getTargetAddress() << ")");
                            dv->setDest(l);
                        }
                    }*/
                    auto extSym = v->getExternalSymbol();
                    if(!extSym->getResolved()) {
                        auto l = PerfectLinkResolver().resolveExternallyStrongWeak(
                            extSym, conductor, module, true, /*afterMapping=*/ true);
                        if(l) {
                            LOG(0, "change CopyRelocLink in " << module->getName()
                                << " from [" << extSym->getName() << "] => " << l << " (0x"
                                << std::hex << l->getTargetAddress() << ")");
                            dv->setDest(l);
                        }
                    }
                }
                else if(auto v = dynamic_cast<InternalAndExternalDataLink *>(link)) {
                    //if(!dv->getIsCopy()) {
                        auto extSym = v->getExternalSymbol();
                        auto l = reResolveTarget(extSym, conductor, module);
                        if(l) {
                            LOG(0, "change InternalAndExternalDataLink in "
                                << module->getName() << " from ["
                                << extSym->getName() << "] => " << l
                                << " (0x" << std::hex << l->getTargetAddress() << ")");
                            dv->setDest(l);
                            delete link;
                        }
                    //}
                }
                else if(auto v = dynamic_cast<ExternalSymbolLink *>(link)) {
                    auto extSym = v->getExternalSymbol();
                    if(v->getOffset() > 0) {
                        LOG(0, "special case");
                    }
                    auto l = reResolveTarget(extSym, conductor, module, v->getOffset());
                    LOG(0, "Original external symbol link target = 0x"
                        << std::hex << v->getTargetAddress());
                    if(l) {
                        LOG(0, "change ExternalSymbolLink from ["
                            << extSym->getName() << "]+" << v->getOffset() << " => "
                            << typeid(*l).name() << " (0x"
                            << std::hex << l->getTargetAddress() << ")");
                        dv->setDest(l);
                        delete link;
                    }
                }
            }
        }
    }
}
