#include "relocdata.h"
#include "elf/elfmap.h"
#include "elf/reloc.h"
#include "chunk/aliasmap.h"
#include "conductor/conductor.h"
#include "log/log.h"

Function *FindAnywhere::findAnywhere(const char *target) {
    if(!conductor) return nullptr;

    for(auto library : *conductor->getLibraryList()) {
        auto elfSpace = library->getElfSpace();
        if(!elfSpace) continue;
        auto module = elfSpace->getModule();
        //auto found = module->getChildren()->getNamed()->find(target);

        auto found = elfSpace->getAliasMap()->find(target);

        if(found) {
            this->elfSpace = elfSpace;
            return found;
        }
    }

    return nullptr;
}

void RelocDataPass::visit(Module *module) {
    //auto children = module->getChildren();

    for(auto r : *relocList) {
        if(!r->getSymbol()) continue;

        LOG(1, "trying to fix " << r->getSymbol()->getName());

        //Function *target = children->getNamed()->find(r->getSymbol()->getName());
        FindAnywhere found(conductor);
        auto target = found.findAnywhere(r->getSymbol()->getName());
        if(!target) continue;

        LOG(1, "FOUND ANYWHERE " << r->getSymbol()->getName());

#ifdef ARCH_X86_64
        if(r->getType() == R_X86_64_GLOB_DAT) {
            address_t update = elf->getBaseAddress() + r->getAddress();
            address_t dest = found.getElfSpace()->getElfMap()->getBaseAddress()
                + target->getAddress();
            LOG(1, "fix address " << update << " to point at "
                << dest);
            *(unsigned long *)update = dest;
        }
        else {
            LOG(1, "NOT fixing because type is " << r->getType());
        }
#endif
    }
}
