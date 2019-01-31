#include <cstring>
#include <cassert>
#include <typeinfo>
#include "handlecopyrelocs.h"
#include "conductor/conductor.h"
#include "elf/elfmap.h"
#include "elf/elfspace.h"

#include "log/log.h"
#include "log/temp.h"

void HandleCopyRelocs::visit(Module *module) {
    if(!module->getElfSpace()) return;

    this->module = module;

    //TemporaryLogLevel tll("pass", 15);
    auto relocList = module->getElfSpace()->getRelocList();
    if(!relocList) return;

    for(auto r : *relocList) {
        if(r->getType() == R_X86_64_COPY) {
            //TemporaryLogLevel tll("chunk", 15);

            assert(module->getName() == "module-(executable)");

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
                auto addr = module->getElfSpace()->getElfMap()->getBaseAddress()
                    + r->getAddress();
                auto region = module->getDataRegionList()->findRegionContaining(addr);
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
                auto addr = module->getElfSpace()->getElfMap()->getBaseAddress()
                    + r->getAddress();
                size_t size = r->getSymbol()->getSize();
                copyAndDuplicate(link, addr, size);
                delete link;
            }
        }
    }
}

void HandleCopyRelocs::copyAndDuplicate(Link *link, address_t address,
    size_t size) {

    auto from = link->getTargetAddress();
    std::memcpy((void *)address, (void *)from, size);
    LOG(0, "copy from " << std::hex << from << " to " << address
        << " size " << size);
    LOG(0, "the value is " << std::hex <<  *(unsigned long *)address);

    Range range(from, size);
    auto section = dynamic_cast<DataSection *>(&*link->getTarget());
    std::vector<DataVariable *> existing;
    for(auto var : CIter::children(section)) {
        LOG(1, "var = " << std::hex << var->getAddress());
        if(range.contains(var->getAddress())) {
            if(dynamic_cast<NormalLink *>(var->getDest())) {
                existing.push_back(var);
            }
        }
    }
    if(!existing.empty()) {
        LOG(0, "copyAndDuplicate: duplication is NYI");
    }
}
