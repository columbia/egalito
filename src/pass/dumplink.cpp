#include <sstream>
#include "dumplink.h"
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

    this->mapbase = module->getElfSpace()->getElfMap()->getBaseAddress();

    ClearSpatialPass clearSpatial;
    module->accept(&clearSpatial);
    for(auto region : CIter::regions(module)) {
        region->accept(&clearSpatial);
    }

    if(auto relocList = module->getElfSpace()->getRelocList()) {
        for(auto r : *relocList) {
            dump(r, module);
        }
    }
    recurse(module);
}

void DumpLinkPass::visit(Instruction *instruction) {
    if(auto link = instruction->getSemantic()->getLink()) {
        if(dynamic_cast<PLTLink *>(link)) return;

        auto semantic = instruction->getSemantic();
        size_t offset = 0;
#ifdef ARCH_X86_64
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

void DumpLinkPass::dump(Reloc *reloc, Module *module) {

    Chunk *inner = ChunkFind().findInnermostInsideInstruction(
        module->getFunctionList(), reloc->getAddress());
    if(auto i = dynamic_cast<Instruction *>(inner)) {
        if(auto link = i->getSemantic()->getLink()) {
            fprintf(stderr, "    0x%-20lx 0x%-20lx",
                 reloc->getAddress(), link->getTargetAddress());
            if(auto target = link->getTarget()) {
                fprintf(stderr, " %s\n", target->getName().c_str());
            }
            else { fprintf(stderr, "\n"); }
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

