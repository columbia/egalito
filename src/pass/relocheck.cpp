#include <sstream>
#include "relocheck.h"
#include "chunk/chunk.h"
#include "chunk/concrete.h"
#include "elf/elfspace.h"
#include "instr/concrete.h"
#include "operation/find.h"
#include "pass/clearspatial.h"

#include "log/log.h"
#include "log/temp.h"
#include "chunk/dump.h"

void ReloCheckPass::visit(Module *module) {
    LOG(1, "-- checking relocation for module " << module->getName());

    ClearSpatialPass clearSpatial;
    module->accept(&clearSpatial);
    for(auto region : CIter::regions(module)) {
        region->accept(&clearSpatial);
    }

    ChunkDumper dumper;
    for(auto region : CIter::regions(module)) {
        IF_LOG(10) region->accept(&dumper);
    }
    if(auto relocList = module->getElfSpace()->getRelocList()) {
        for(auto r : *relocList) {
            check(r, module);
        }
    }
    recurse(module);
    checkDataVariable(module);
    LOG(1, "-- end");
}

void ReloCheckPass::visit(Instruction *instruction) {
    UnresolvedLink *link = nullptr;
    if(auto v = dynamic_cast<LinkedInstruction *>(
        instruction->getSemantic())) {

        link = dynamic_cast<UnresolvedLink *>(v->getLink());
    }
    if(auto v = dynamic_cast<ControlFlowInstruction *>(
        instruction->getSemantic())) {

        link = dynamic_cast<UnresolvedLink *>(v->getLink());
    }

    if(link) {
        LOG(1, " unresolved link at " << std::hex
            << instruction->getAddress()
            << " to " << link->getTargetAddress());
        auto f = dynamic_cast<Function *>(
            instruction->getParent()->getParent());
        LOG(10, " in " << f->getName() << " at " << f->getAddress());
#if defined(ARCH_AARCH64)
        if(dynamic_cast<LinkedLiteralInstruction *>(
            instruction->getSemantic())) {

            LOG(10, "    from linkedliteral!");
        }
#endif
    }
}

void ReloCheckPass::checkDataVariable(Module *module) {
    for(auto region : CIter::regions(module)) {
        for(auto var : region->variableIterable()) {
            if(var->getDest()->getTarget()) {
                continue;
            }
            else if(dynamic_cast<MarkerLink *>(var->getDest())) {
                LOG(1, "var " << var->getAddress() << " has a marker link");
            }
            else if(dynamic_cast<SymbolOnlyLink *>(var->getDest())) {
                LOG(1, "var " << var->getAddress() << " symbol only link");
            }
            else {
                LOG0(1, " var with unresolved link at " << var->getAddress());
            }
        }
    }
}

static bool linkCheck(Reloc *r, Link *link, const std::stringstream &ss) {
    if(dynamic_cast<UnresolvedLink *>(link)) {
        LOG0(1, ss.str() << " NOT resolved!! ");
        if(r->getSymbol()) {
            LOG(1, std::hex << r->getSymbol()->getAddress()
                << "(" << r->getSymbol()->getName() << ")");
        }
        else LOG(1, "");
        return false;
    }
    else {
        LOG(10, ss.str()
            << " resolved to " << link->getTarget()->getName()
            << " (" << link->getTargetAddress() << ")");
        return true;
    }
}

/*
 * there are two cases for unresolved:
 * (1) a symbol is defined in linker script which is outside the data regions
 * (2) a symbol is weak but not defined
 */
void ReloCheckPass::check(Reloc *r, Module *module) {
    std::stringstream ss;

#ifdef ARCH_X86_64
    if(r->getType() == R_X86_64_NONE) return;
#endif

    ss << "relocation at " << std::hex << r->getAddress() << " with addend "
        << r->getAddend();
    auto flist = module->getFunctionList();
    Chunk *inner
        = ChunkFind().findInnermostInsideInstruction(flist, r->getAddress());
    if(auto i = dynamic_cast<Instruction *>(inner)) {
        if(auto v = dynamic_cast<LinkedInstruction *>(i->getSemantic())) {
            auto check = linkCheck(r, v->getLink(), ss);
            if(!check) {
                LOG(1, "    linkCheck failed for LinkedInstruction");
            }
        }
#ifdef ARCH_X86_64
        else if(auto v
            = dynamic_cast<ControlFlowInstruction *>(i->getSemantic())) {

            auto check = linkCheck(r, v->getLink(), ss);
            if(!check) {
                LOG(1, "    linkCheck failed for ControlFlowInstruction");
            }
        }
#endif
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
        DataVariable *var = nullptr;
        if(tls &&
            Range(tls->getOriginalAddress(), tls->getSize()).contains(addr)) {

            auto tlsAddr = addr + tls->getAddress() - tls->getOriginalAddress();
            var = tls->findVariable(tlsAddr);
        }
        if(!var) {
            auto dlist = module->getDataRegionList();
            if(auto region = dlist->findRegionContaining(addr)) {
                var = region->findVariable(addr);
            }
        }

        if(var) {
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
                LOG0(1, ss.str() << " NOT resolved!!!");
                auto link = dynamic_cast<TLSDataOffsetLink *>(var->getDest());
                if(link) {
                    if(auto sym = link->getSymbol()) {
                        if(sym->getBind() == Symbol::BIND_WEAK) {
                            LOG0(1, " [WEAK]");
                        }
                    }
                    LOG(1, "");
                }
                else {
                    LOG(1, std::hex << var->getDest()->getTargetAddress());
                }
            }
        }
        else {
            LOG0(1, ss.str() << " NOT resolved! (no variable)");
            if(auto sym = r->getSymbol()) {
                if(sym->getBind() == Symbol::BIND_WEAK) {
                    LOG(1, " [WEAK] " << sym->getName());
                }
                else {
                    LOG(1, std::hex << r->getSymbol()->getAddress()
                        << "(" << r->getSymbol()->getName() << ")");
                }
            }
            else LOG(1, "");
        }
    }
}
