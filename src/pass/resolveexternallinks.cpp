#include <typeinfo>
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
                    auto symbol = dv->getTargetSymbol();
                    auto l = reResolveTarget(symbol, conductor, module);
                    if(l) {
                        LOG(0, "change null link from ["
                            << symbol->getName() << "] => " << l << ", " << typeid(*l).name());
                        dv->setDest(l);
                    }
                }
                else if(auto v = dynamic_cast<InternalAndExternalDataLink *>(link)) {
                    auto extSym = v->getExternalSymbol();
                    auto l = reResolveTarget(extSym, conductor, module);
                    if(l) {
                        LOG(0, "change InternalAndExternalDataLink from ["
                            << extSym->getName() << "] => " << l << " (" << std::hex << l->getTargetAddress() << ")");
                        dv->setDest(l);
                        delete link;
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
