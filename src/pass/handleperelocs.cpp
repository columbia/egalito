#include <typeinfo>

#include "handleperelocs.h"
#include "pe/pemap.h"
#include "chunk/link.h"
#include "chunk/dataregion.h"
#include "elf/reloc.h"
#include "exefile/exefile.h"

#include "log/log.h"

void HandlePERelocsPass::visit(Module *module) {
    auto peFile = ExeAccessor::file<PEExeFile>(module);
    if(!peFile) return;

    auto relocList = peFile->getRelocList();
    if(!relocList) return;

    for(auto reloc : *relocList) {
        auto address = reloc->getAddress();
        auto link = makeLink(module, reloc);
        if(link) {
            DataVariable::create(module, address, link, reloc->getSymbol());
        }
    }
}

Link *HandlePERelocsPass::makeLink(Module *module, Reloc *reloc) {
    auto peMap = ExeAccessor::map<PEMap>(module);
    switch(reloc->getType()) {    
    case peparse::ABSOLUTE:
        return nullptr;  // relocation type is skipped by definition
    case peparse::HIGH:
    case peparse::LOW:
    case peparse::HIGHLOW:
    case peparse::HIGHADJ:
        return nullptr;
    case peparse::DIR64: {
        auto read = peMap->getReadAddress<address_t *>(reloc->getAddress());
        auto target = *read - peMap->getPEImageBase(); // + module->getBaseAddress();
        auto link = LinkFactory::makeDataLink(module, target, false);

        LOG(0, "    read 0x" << std::hex << reloc->getAddress() << " -> 0x" << target
            << ", link is " << link << " " << (link ? typeid(*link).name() : "null"));
        return link;
    }
    default:
        return nullptr;
    }
}
