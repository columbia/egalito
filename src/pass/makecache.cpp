#include "makecache.h"

void MakeCachePass::visit(Function *function) {
#ifdef ARCH_X86_64
    function->makeCache();
#endif
}

void MakeCachePass::visit(PLTTrampoline *trampoline) {
#ifdef ARCH_X86_64
    trampoline->makeCache();
#endif
}
