#include <cstring>
#include <cassert>
#include "handlecopyrelocs.h"
#include "conductor/conductor.h"
#include "elf/elfmap.h"
#include "elf/elfspace.h"

#include "log/log.h"
#include "log/temp.h"

void HandleCopyRelocs::visit(Module *module) {
    if(!module->getElfSpace()) return;

    this->module = module;

    //TemporaryLogLevel tll("pass", 10);
    auto relocList = module->getElfSpace()->getRelocList();
    if(!relocList) return;

    for(auto r : *relocList) {
        if(r->getType() == R_X86_64_COPY) {
            //TemporaryLogLevel tll("chunk", 10);

            assert(module->getName() == "module-(executable)");

            LOG(10, "R_X86_64_COPY!! at " << r->getAddress());
            auto link = PerfectLinkResolver().resolveExternally(
                r->getSymbol(), conductor, module->getElfSpace(),
                false, false, true);
            if(!link) {
                link = PerfectLinkResolver().resolveExternally(
                    r->getSymbol(), conductor, module->getElfSpace(),
                    true, false, true);
            }
            if(!link) {
                LOG(1, "no link found for R_X86_64_COPY");
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
    LOG(10, "copy from " << std::hex << from << " to " << address
        << " size " << size);

    Range range(from, size);
    auto section = dynamic_cast<DataSection *>(&*link->getTarget());
    std::vector<DataVariable *> existing;
    for(auto var : CIter::children(section)) {
        LOG(11, "var = " << std::hex << var->getAddress());
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
