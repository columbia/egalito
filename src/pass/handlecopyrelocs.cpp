#include <cstring>
#include <cassert>
#include <typeinfo>
#include "handlecopyrelocs.h"
#include "conductor/conductor.h"
#include "chunk/link.h"
#include "chunk/resolver.h"
#include "elf/elfmap.h"
#include "elf/elfspace.h"

#include "log/log.h"
#include "log/temp.h"

#if 0
void HandleCopyRelocs::visit(Module *module) {
    if(module->getLibrary()->getRole() != Library::ROLE_MAIN) return;
    if(!module->getElfSpace()) return;

    //TemporaryLogLevel tll("pass", 15);
    auto relocList = module->getElfSpace()->getRelocList();
    if(!relocList) return;

    for(auto r : *relocList) {
        if(r->getType() == R_X86_64_COPY) {
            //TemporaryLogLevel tll("chunk", 15);

            LOG(10, "R_X86_64_COPY!! at " << r->getAddress());
            LOG(10, "    symbol: " << r->getSymbol());
            auto link = PerfectLinkResolver().resolveExternally(
                r->getSymbol(), conductor, module->getElfSpace(),
                false, false, true);

            // don't resolve weak symbols because we don't want targets within the same module

            if(!link) {
                auto externalSymbol = ExternalSymbolFactory(module)
                    .makeExternalSymbol(r->getSymbol());
                link = new CopyRelocLink(externalSymbol);
                LOG(1, "no link found for R_X86_64_COPY");
                LOG(1, "update DataVariable to be isCopy");
                // create a copy DataVariable
                auto addr = module->getBaseAddress() + r->getAddress();
                auto region = module->getDataRegionList()->findRegionContaining(addr);
                if(!region) {
                    LOG(1, "ERROR: Could not find region containing 0x"
                        << std::hex << addr << " ["
                        << r->getSymbol()->getName() << "]");
                    continue;
                }
                auto var = region->findVariable(addr);
                if(var) {
                    var->setIsCopy(true);
                    var->setDest(link);
                    var->setSize(r->getSymbol()->getSize());
                }
                else {
                    /* for now, this shouldn't happen since HandleDataRelocs goes first. */
                    LOG(1, "WARNING: shouldn't HandleDataRelocs have handled this?");
                    auto section = region->findDataSectionContaining(addr);
                    auto var = DataVariable::create(section, addr, link, r->getSymbol());
                    var->setSize(r->getSymbol()->getSize());
                }

                continue;
            }
            else {
                auto addr = module->getBaseAddress() + r->getAddress();
                size_t size = r->getSymbol()->getSize();
                copyAndDuplicate(link, addr, size);
                delete link;
            }
        }
    }
}
#else
void HandleCopyRelocs::visit(Module *module) {
    if(module->getLibrary()->getRole() != Library::ROLE_MAIN) return;

    for(auto region : CIter::regions(module)) {
        for(auto section : CIter::children(region)) {
            for(auto var : CIter::children(section)) {
                if(!var->getIsCopy()) continue;

                // NOTE: Addresses must include the base address, we are memcpy'ing
                copyAndDuplicate(var->getDest(), var->getAddress(), var->getSize());
            }
        }
    }
}
#endif

void HandleCopyRelocs::copyAndDuplicate(Link *sourceLink, address_t destAddress,
    size_t size) {

    auto sourceAddress = sourceLink->getTargetAddress();
    if(!sourceAddress || !destAddress) return;

    std::memcpy((void *)destAddress, (void *)sourceAddress, size);
    LOG(0, "copy from 0x" << std::hex << sourceAddress << " to 0x" << destAddress
        << " size " << size);
    LOG(0, "the value is 0x" << std::hex << *(unsigned long *)destAddress);
}
