#include <assert.h>

#include "linked-riscv.h"
#include "config.h"

#include "chunk/link.h"
#include "chunk/concrete.h"
#include "analysis/dataflow.h"
#include "analysis/liveregister.h"
#include "analysis/pointerdetection.h"

#include "log/log.h"

#ifdef ARCH_RISCV

void LinkedInstruction::writeTo(char *target, bool useDisp) {
    *reinterpret_cast<uint32_t *>(target) = rebuild();
}

void LinkedInstruction::writeTo(std::string &target, bool useDisp) {
    uint32_t data = rebuild();
    target.append(reinterpret_cast<const char *>(&data), getSize());
}

uint32_t LinkedInstruction::rebuild() {
    assert(0);
    return 0;
}

void LinkedInstruction::makeAllLinked(Module *module) {
    DataFlow df;
    LiveRegister live;
    PointerDetection pd;
    for(auto func : CIter::functions(module)) {
        df.addUseDefFor(func);
    }
    for(auto func : CIter::functions(module)) {
        live.detect(df.getWorkingSet(func));
    }
    for(auto func : CIter::functions(module)) {
        df.adjustCallUse(&live, func, module);
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
