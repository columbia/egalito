#include <utility>
#include <vector>

#include "makereloc.h"
#include "pemap.h"
#include "elf/reloc.h"
#include "exefile/symbol.h"

#include "log/log.h"

RelocList *PEMakeReloc::buildRelocList(PEMap *peMap, SymbolList *symbolList,
    SymbolList *dynamicSymbolList) {
    
    using namespace peparse;
    auto peRef = peMap->getPERef();
    std::vector<std::pair<address_t, reloc_type>> relocData;
    IterRelocs(peRef, [] (void *_data,
        peparse::VA address, peparse::reloc_type type) {

        auto &relocData = *reinterpret_cast<
            std::vector<std::pair<address_t, reloc_type>> *>(_data);

        relocData.push_back(std::make_pair(address, type));
        return 0;
    }, &relocData);

    RelocList *list = new RelocList();
    for(const auto &d : relocData) {
        address_t address = d.first;
        reloc_type type = d.second;

        // pe-parse adds the base address to reloc addresses, we undo this.
        address_t baseAddress = peRef->peHeader.nt.OptionalHeader64.ImageBase;
        address -= baseAddress;

        LOG(1, "    reloc 0x" << std::hex << address << " with type 0x" << type);
        Reloc *reloc = new Reloc(
            address,   // address
            type,      // type
            0,         // symbol index
            nullptr,   // Symbol*
            0          // addend
        );

        if(!list->add(reloc)) {
            CLOG0(1, "ignoring duplicate relocation for %lx\n",
                  reloc->getAddress());
        }
        /*else {
            list->makeOrGetSection(".reloc", s)->add(reloc);
        }*/
    }
    return list;
}
