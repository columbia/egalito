#include <assert.h>

#include "linked-riscv.h"
#include "config.h"

#include "chunk/link.h"
#include "chunk/resolver.h"
#include "chunk/concrete.h"
#include "analysis/dataflow.h"
#include "analysis/liveregister.h"
#include "analysis/pointerdetection.h"
#include "analysis/walker.h"

#include "log/log.h"

#ifdef ARCH_RISCV

void LinkedInstruction::regenerateAssembly() {
    LOG(10, "assembly regeneration NYI for RISC-V");
}

void LinkedInstruction::writeTo(char *target, bool useDisp) {
    if(getSize() == 2) {
        *reinterpret_cast<uint16_t *>(target) = rebuild();
    }
    else if(getSize() == 4) {
        *reinterpret_cast<uint32_t *>(target) = rebuild();
    }
    else assert(0);
}

void LinkedInstruction::writeTo(std::string &target, bool useDisp) {
    uint32_t data = rebuild();
    target.append(reinterpret_cast<const char *>(&data), getSize());
}

uint32_t LinkedInstruction::rebuild() {
    LOG(10, "assembly rebuilding NYI for RISC-V");
    if(getSize() == 2) {
        return *(uint16_t *)(instruction->getSemantic()->getData().data());
    }
    else if(getSize() == 4) {
        return *(uint32_t *)(instruction->getSemantic()->getData().data());
    }
    else assert("RISC-V instruction size is not 16 or 32 bits" && 0);
    return 0;
}

void LinkedInstruction::makeAllLinked(Module *module) {
    LOG(0, "Finding split pointers in module " << module->getName());

    DataFlow df;
    PointerDetection pd;
    for(auto func : CIter::functions(module)) {
        df.addUseDefFor(func);
    }
    for(auto func : CIter::functions(module)) {
        pd.detect(df.getWorkingSet(func));
    }

    resolveLinks(module, pd.getList());
}

void LinkedInstruction::resolveLinks(Module *module,
    const std::vector<std::pair<Instruction *, address_t>>& list) {
    // stolen wholesale from aarch64 implementation

    //TemporaryLogLevel tll("instr", 10);
    for(auto it : list) {
        auto instruction = it.first;
        auto address = it.second;
        LOG(10, "pointer at 0x" << std::hex << instruction->getAddress()
            << " pointing to 0x" << address);
        auto assembly = instruction->getSemantic()->getAssembly();
        auto linked = new LinkedInstruction(instruction);
        linked->setAssembly(assembly);

        auto link = PerfectLinkResolver().resolveInferred(
            address, instruction, module, true);

        if(!link && assembly->getImplicitRegsWriteCount() > 0
            && assembly->getImplicitRegsWrite()[0] == rv_ireg_gp) {

            LOG(1, "GP setup link found!");
            auto gpmarker
                = module->getMarkerList()->addGlobalPointerMarker(address);
            link = new AbsoluteMarkerLink(gpmarker);
            //link = module->getMarkerList()->createInferredMarkerLink(
                //address, module, true);
        }
        if(link) {
            linked->setLink(link);
            auto v = instruction->getSemantic();
            instruction->setSemantic(linked);
            delete v;
            continue;
        }
        assert("[LinkedInstruction] failed to create link!" && 0);
    }
}

#endif
