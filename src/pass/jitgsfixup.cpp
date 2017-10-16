#include "jitgsfixup.h"
#include "switchcontext.h"
#include "chunk/concrete.h"
#include "conductor/conductor.h"
#include "operation/find2.h"
#include "cminus/print.h"
#include "snippet/hook.h"
#include "log/log.h"

extern "C"
void egalito_jit_gs_fixup(unsigned long address) {
    egalito_printf("(JIT-fixup 0x%lx)\n", address);
}

JitGSFixup::JitGSFixup(Conductor *conductor, GSTable *gsTable)
    : conductor(conductor), gsTable(gsTable) {

}

void JitGSFixup::visit(Program *program) {
    auto lib = conductor->getLibraryList()->get("(egalito)");
    if(!lib) throw "JitGSFixup requires libegalito.so to be transformed";

    callback = ChunkFind2(conductor).findFunctionInModule(
        "egalito_hook_jit_fixup", lib->getElfSpace()->getModule());
    if(!callback) {
        throw "JitGSFixup can't find hook function";
    }

    SwitchContextPass switcher;
    callback->accept(&switcher);

    set_jit_fixup_hook(egalito_jit_gs_fixup);

    resetGSTable();
}

void JitGSFixup::resetGSTable() {
    for(auto entry : CIter::children(gsTable)) {
        LOG(1, "set resolver for " << entry->getTarget()->getName());
        entry->setLazyResolver(callback);
    }
}
