#include "makecache.h"

void MakeCachePass::visit(Function *function) {
    function->makeCache();
}

void MakeCachePass::visit(PLTTrampoline *trampoline) {
    trampoline->makeCache();
}
