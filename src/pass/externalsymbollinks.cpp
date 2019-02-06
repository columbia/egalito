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
#if 0
                    if(externalSymbol->getLocalWeakInstance()) {
                        auto sym = dv->getTargetSymbol();
                        auto section = module->getElfSpace()->getElfMap()->findSection(
                            sym->getSectionIndex());
                        auto dataSection = module->getDataRegionList()->findDataSection(
                            section->getName());
                        auto offset = sym->getAddress() - section->getVirtualAddress();
                        externalSymbol->setPosition(new AbsoluteOffsetPosition(
                            externalSymbol, offset));
                    }
#endif
                }
                else {
                    auto link = new CopyRelocLink(externalSymbol);
                    dv->setDest(link);
                }
            }
        }
    }
}
