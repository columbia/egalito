#include "externalsymbollinks.h"
#include "chunk/link.h"
#include "log/log.h"
#include "log/temp.h"

void ExternalSymbolLinksPass::visit(Module *module) {
    for(auto dr : CIter::regions(module)) {
        for(auto ds : CIter::children(dr)) {
            for(auto dv : CIter::children(ds)) {
                if(dv->getDest()) continue;

                auto externalSymbol = ExternalSymbolFactory(module)
                    .makeExternalSymbol(dv->getTargetSymbol());
                auto link = new ExternalSymbolLink(externalSymbol);
                dv->setDest(link);
            }
        }
    }
}
