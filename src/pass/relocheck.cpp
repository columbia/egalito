#include <sstream>
#include "relocheck.h"
#include "chunk/chunk.h"
#include "chunk/concrete.h"
#include "elf/elfspace.h"
#include "instr/concrete.h"
#include "operation/find.h"
#include "log/log.h"

void ReloCheckPass::visit(Module *module) {
    LOG(1, "-- checking relocation for module " << module->getName());
#if defined(ARCH_AARCH64) || defined(ARCH_ARM)
    if(auto relocList = module->getElfSpace()->getRelocList()) {
        for(auto r : *relocList) {
            check(r, module);
        }
    }
#endif
    LOG(1, "-- end");
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
                LOG(1, ss.str() << " NOT resolved!! " << std::hex
                    << r->getSymbol()->getAddress());
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
                LOG(1, ss.str() << " NOT resolved!");
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
        auto addr = module->getElfSpace()->getElfMap()->getBaseAddress()
            + r->getAddress();
        auto dlist = module->getDataRegionList();
        if(auto region = dlist->findRegionContaining(addr)) {
            if(auto var = region->findVariable(addr)) {
                if(var->getDest()->getTarget()) {
                    LOG(10, ss.str() << " resolved as a data variable pointing to "
                        << var->getDest()->getTarget()->getName()
                        << " at " << var->getDest()->getTargetAddress());
                }
                else {
                    LOG(1, ss.str() << " NOT resolved!!!");
                }
            }
            else {
                LOG(1, ss.str() << " NOT resolved! " << std::hex
                    << r->getSymbol()->getAddress());
            }
        }
        else {
            LOG(1, "region not found for " << addr);
        }
    }
}
