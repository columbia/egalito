#include "jitgsfixup.h"
#include "switchcontext.h"
#include "chunk/concrete.h"
#include "conductor/conductor.h"
#include "operation/find2.h"
#include "cminus/print.h"
#include "snippet/hook.h"
#include "runtime/managegs.h"
#include "log/log.h"

GSTable *egalito_gsTable;

extern "C"
void egalito_jit_gs_fixup(unsigned long *address) {
    //egalito_printf("(JIT-fixup 0x%lx)\n", address);

    uint32_t offset = *reinterpret_cast<uint32_t *>(*address - 4);
    uint32_t index = egalito_gsTable->offsetToIndex(offset);

    egalito_printf("(JIT-fixup address=0x%lx index=%d ", *address, index);

    auto entry = egalito_gsTable->getAtIndex(index);
    if(entry) {
        entry->setLazyResolver(nullptr);
        auto target = entry->getTarget();
        egalito_printf("target=[%s])\n", target->getName().c_str());

        ManageGS::setEntry(egalito_gsTable, index, target->getAddress());
        *address -= 8;  // size of call instruction; re-run it
    }
    else {
        egalito_printf("JIT jump error, target not known! Will likely crash.\n");
    }
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

    ::egalito_gsTable = gsTable;
    resetGSTable();
}

void JitGSFixup::resetGSTable() {
    for(auto entry : CIter::children(gsTable)) {
        LOG(1, "set resolver for " << entry->getTarget()->getName());
        entry->setLazyResolver(callback);
    }
}
