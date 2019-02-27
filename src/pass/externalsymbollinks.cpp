#include "externalsymbollinks.h"
#include "chunk/link.h"
#include "chunk/position.h"
#include "elf/elfspace.h"
#include "elf/elfmap.h"
#include "log/log.h"
#include "log/temp.h"

void ExternalSymbolLinksPass::visit(Module *module) {
    for(auto dr : CIter::regions(module)) {
        for(auto ds : CIter::children(dr)) {
            for(auto dv : CIter::children(ds)) {
                if(dv->getDest()) continue;

                // If no target symbol, relocation type is probably not supported
                if(!dv->getTargetSymbol()) continue;

                auto externalSymbol = ExternalSymbolFactory(module)
                    .makeExternalSymbol(dv->getTargetSymbol());
                if(!dv->getIsCopy()) {
                    auto link = new ExternalSymbolLink(externalSymbol);
                    dv->setDest(link);
                }
                else {
                    auto link = new CopyRelocLink(externalSymbol);
                    dv->setDest(link);
                }
            }
        }
    }
}
