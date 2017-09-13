#include <sstream>
#include "relocheck.h"
#include "chunk/chunk.h"
#include "chunk/concrete.h"
#include "elf/elfspace.h"
#include "instr/concrete.h"
#include "operation/find.h"
#include "pass/clearspatial.h"

#include "log/log.h"
#include "chunk/dump.h"

void ReloCheckPass::visit(Module *module) {
#if defined(ARCH_AARCH64) || defined(ARCH_ARM)
    LOG(1, "-- checking relocation for module " << module->getName());

    ClearSpatialPass clearSpatial;
    module->accept(&clearSpatial);
    for(auto region : CIter::regions(module)) {
        region->accept(&clearSpatial);
    }

    ChunkDumper dumper;
    for(auto region : CIter::regions(module)) {
        region->accept(&dumper);
    }
    if(auto relocList = module->getElfSpace()->getRelocList()) {
        for(auto r : *relocList) {
            check(r, module);
        }
    }
    LOG(1, "-- end");
#endif
}

/*
 * there are two cases for unresolved:
 * (1) a symbol is defined in linker script which is outside the data regions
 * (2) a symbol is weak but not defined
 */
void ReloCheckPass::check(Reloc *r, Module *module) {
    std::stringstream ss;

    ss << "relocation at " << std::hex << r->getAddress() << " with addend "
        << r->getAddend();
    auto flist = module->getFunctionList();
    Chunk *inner
        = ChunkFind().findInnermostInsideInstruction(flist, r->getAddress());
    if(auto i = dynamic_cast<Instruction *>(inner)) {
        if(auto v = dynamic_cast<LinkedInstruction *>(i->getSemantic())) {
            if(dynamic_cast<UnresolvedLink *>(v->getLink())) {
                LOG0(1, ss.str() << " NOT resolved!! ");
                if(r->getSymbol()) {
                    LOG(1, std::hex << r->getSymbol()->getAddress()
                        << "(" << r->getSymbol()->getName() << ")");
                }
                else LOG(1, "");
            }
            else {
                LOG(10, ss.str()
                    << " resolved to " << v->getLink()->getTarget()->getName()
                    << " (" << v->getLink()->getTargetAddress() << ")");
            }
        }
#ifdef ARCH_AARCH64
        else if(auto v
            = dynamic_cast<LinkedLiteralInstruction *>(i->getSemantic())) {

            if(dynamic_cast<UnresolvedLink *>(v->getLink())) {
                LOG(1, ss.str() << " NOT resolved! (unresolved link)");
            }
            else {
                LOG(10, ss.str()
                    << " resolved to " << v->getLink()->getTarget()->getName()
                    << " (" << v->getLink()->getTargetAddress() << ")");
            }
        }
#endif
        else {
            LOG(1, i->getName() << " is still DisassembledInstruction");
        }
    }
    else {
        address_t addr = r->getAddress();
        auto tls = module->getDataRegionList()->getTLS();
        if(tls &&
           Range(tls->getOriginalAddress(), tls->getSize()).contains(addr)) {

            addr += tls->getAddress() - tls->getOriginalAddress();
        }
        else {
            addr += module->getElfSpace()->getElfMap()->getBaseAddress();
        }

        auto dlist = module->getDataRegionList();
        if(auto region = dlist->findRegionContaining(addr)) {
            if(auto var = region->findVariable(addr)) {
                if(var->getDest()->getTarget()) {
                    LOG(10, ss.str() << " resolved as a data variable pointing to "
                        << var->getDest()->getTarget()->getName()
                        << " at " << var->getDest()->getTargetAddress());
                }
                else if(dynamic_cast<MarkerLink *>(var->getDest())) {
                    LOG(10, ss.str()
                        << " resolved as a data variable pointing to a marker");
                }
                else if(dynamic_cast<SymbolOnlyLink *>(var->getDest())) {
                    LOG(10, ss.str()
                        << " resolved as a data variable pointing to loader emulator");
                }
                else {
                    LOG(1, ss.str() << " NOT resolved!!!");
                }
            }
            else {
                LOG0(1, ss.str() << " NOT resolved! (no variable)");
                if(auto sym = r->getSymbol()) {
                    if(sym->getBind() == Symbol::BIND_WEAK) {
                        LOG(1, "WEAK");
                    }
                    else {
                        LOG(1, std::hex << r->getSymbol()->getAddress()
                            << "(" << r->getSymbol()->getName() << ")");
                    }
                }
                else LOG(1, "");
            }
        }
        else {
            LOG(1, "region not found for " << addr);
        }
    }
}
