#include <sstream>
#include "dumplink.h"
#include "analysis/jumptable.h"
#include "chunk/chunk.h"
#include "chunk/concrete.h"
#include "elf/elfspace.h"
#include "instr/concrete.h"
#include "operation/find.h"
#include "pass/clearspatial.h"

#include "log/log.h"
#include "log/temp.h"
#include "chunk/dump.h"

void DumpLinkPass::visit(Module *module) {
    LOG(11, "Dumping Links for " << module->getName());

    this->module = module;
    this->mapbase = module->getElfSpace()->getElfMap()->getBaseAddress();

    ClearSpatialPass clearSpatial;
    module->accept(&clearSpatial);
    for(auto region : CIter::regions(module)) {
        region->accept(&clearSpatial);
    }

    LOG(11, "    from relocation");
    if(auto relocList = module->getElfSpace()->getRelocList()) {
        for(auto r : *relocList) {
            dump(r, module);
        }
    }
    LOG(11, "    from instruction");
    recurse(module);
    LOG(11, "    from variables");
    recurse(module->getDataRegionList());
}

void DumpLinkPass::visit(Instruction *instruction) {
    if(auto link = instruction->getSemantic()->getLink()) {
        if(dynamic_cast<PLTLink *>(link)) return;

        // for a link to an instruction inside the same function,
        // there will be no relocation even with -q
        if(instruction->getParent()->getParent()
            == link->getTarget()->getParent()->getParent()) {
            return;
        }

        size_t offset = 0;
#ifdef ARCH_X86_64
        auto semantic = instruction->getSemantic();
        if(auto v = dynamic_cast<LinkedInstruction *>(semantic)) {
            offset = v->getDispOffset();
        }
        else if(auto v = dynamic_cast<ControlFlowInstruction *>(semantic)) {
            offset = v->getDispOffset();
        }
#endif
        output(instruction->getAddress() + offset, link);
    }
}

void DumpLinkPass::visit(DataSection *section) {
    std::set<address_t> seen;

    // AARCH64 elf files do not contain relocations for jump tables
    for(auto jt : CIter::children(module->getJumpTableList())) {
#ifdef ARCH_X86_64
        address_t valuebase = jt->getDescriptor()->getAddress();
#endif
        for(auto entry : CIter::children(jt)) {
            auto var = entry->getDataVariable();
#ifdef ARCH_X86_64
            auto link = entry->getLink();
            outputPair(var->getAddress() - mapbase,
                link->getTargetAddress() - valuebase);
#endif
            seen.insert(var->getAddress());
        }
    }
    for(auto var : CIter::children(section)) {
        auto it = seen.find(var->getAddress());
        if(it != seen.end()) continue;
        output(var->getAddress() - mapbase, var->getDest());
    }
}

void DumpLinkPass::dump(Reloc *reloc, Module *module) {

    Chunk *inner = ChunkFind().findInnermostInsideInstruction(
        module->getFunctionList(), reloc->getAddress());
    if(auto i = dynamic_cast<Instruction *>(inner)) {
        if(auto link = i->getSemantic()->getLink()) {
            output(reloc->getAddress(), link);
        }
    }
    else {
        if(auto var = module->getDataRegionList()->findVariable(
            reloc->getAddress() + mapbase)) {
            output(reloc->getAddress(), var->getDest());
        }
    }
}

void DumpLinkPass::output(address_t source, Link *link) {
    if(auto target = link->getTarget()) {
        address_t targetAddress = link->getTargetAddress();
        if(dynamic_cast<DataOffsetLink *>(link)) {
            targetAddress -= mapbase;
        }
        fprintf(stderr, "    0x%-20lx 0x%-20lx", source, targetAddress);
        fprintf(stderr, " %s\n", target->getName().c_str());
    }
}

void DumpLinkPass::outputPair(address_t addr1, address_t addr2) {
    fprintf(stderr, "    0x%-20lx 0x%-20lx\n", addr1, addr2);
}

