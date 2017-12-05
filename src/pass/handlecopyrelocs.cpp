#include <cstring>
#include "handlecopyrelocs.h"
#include "conductor/conductor.h"
#include "elf/elfmap.h"
#include "elf/elfspace.h"

#include "log/log.h"
#include "log/temp.h"
#include "chunk/dump.h"

void HandleCopyRelocs::visit(Module *module) {
    if(!module->getElfSpace()) return;
    auto relocList = module->getElfSpace()->getRelocList();
    if(!relocList) return;

    ChunkDumper d;
    for(auto r : *relocList) {
        if(r->getType() == R_X86_64_COPY) {
            for(auto m : CIter::children(conductor->getProgram())) {
                if(m->getName() == "module-libc.so.6") {
                    m->getDataRegionList()->accept(&d);
                }
            }
            break;
        }
    }

    for(auto r : *relocList) {
        if(r->getType() == R_X86_64_COPY) {
            TemporaryLogLevel tll("chunk", 10);

            LOG(1, "R_X86_64_COPY!!");
            auto link = PerfectLinkResolver().resolveExternally(
                r->getSymbol(), conductor, module->getElfSpace(),
                true);
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

    if(auto dlink = dynamic_cast<DataOffsetLink *>(link)) {
        auto from = dlink->getTargetAddress();
        LOG(1, "copy " << size << " bytes from "
            << std::hex << from << " to " << address);
        std::memcpy((void *)address, (void *)from, size);

        Range range(address, size);
        auto section = dynamic_cast<DataSection *>(&*dlink->getTarget());
        for(auto var : CIter::children(section)) {
            if(range.contains(var->getAddress())) {
                LOG(0, "copyAndDuplicate: NYI"
                    << " (var must be duplicated for the copied data)");
            }
        }
    }
    else if(auto slink = dynamic_cast<SymbolOnlyLink *>(link)) {
        // must be emulated
        auto from = slink->getTargetAddress();
        // look RelocData implementation!!
        LOG(1, "copy " << size << " bytes from "
            << std::hex << from << " to " << address);
        std::memcpy((void *)address, (void *)from, size);
    }
}
