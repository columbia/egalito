#include "reorderpush.h"
#include "analysis/frametype.h"
#include "chunk/module.h"
#include "chunk/function.h"
#include "chunk/dump.h"
#include "log/log.h"

void ReorderPush::visit(Module *module) {
    recurse(module);
}

void ReorderPush::visit(Function *function) {
    FrameType frameType(function);
    frameType.dump();

    for(auto block : CIter::children(function)) {
        for(auto instr : CIter::children(block)) {
            if(dynamic_cast<StackFrameInstruction *>(instr)) {
                LOG0(1, "stack frame instruction: ");
                ChunkDumper dump;
                instr->accept(&dump);
            }
        }
    }
}
