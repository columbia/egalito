#include <cassert>
#include "debloat.h"
#include "analysis/walker.h"
#include "chunk/concrete.h"
#include "elf/elfspace.h"
#include "elf/elfmap.h"
#include "instr/semantic.h"
#include "operation/find2.h"
#include "operation/mutator.h"
#include "util/feature.h"

#include "log/log.h"
#include "log/temp.h"

DebloatPass::DebloatPass(Program *program) : program(program), graph(program) {
    useFromDynamicInitFini();
    useFromEntry();
    useFromIndirectCallee();
    useFromCodeLinks();
    useFromSpecialName();
}

void DebloatPass::visit(Module *module) {
    //TemporaryLogLevel tll("pass", 10);

    int unused = 0;
    for(auto f : CIter::functions(module)) {
        auto it = usedList.find(f);
        if(it == usedList.end()) {
            unused++;
        }
    }

    LOG(1, module->getName() << " has "
        << std::dec << unused << " unnecessary functions (out of "
        << module->getFunctionList()->getChildren()->getIterable()->getCount()
        << ")");
    if(module == program->getMain()) {
        for(auto f : CIter::functions(module)) {
            auto it = usedList.find(f);
            if(it == usedList.end()) {
                LOG(10, " " << f->getName());
            }
        }
    }

    ChunkMutator m(module->getFunctionList());
    for(auto f : CIter::functions(module)) {
        auto it = usedList.find(f);
        if(it == usedList.end()) {
            m.remove(f);
        }
    }
}

void DebloatPass::useFromDynamicInitFini() {
    for(auto module : CIter::children(program)) {
        auto elfMap = module->getElfSpace()->getElfMap();
        auto dynamic = elfMap->findSection(".dynamic");
        if(!dynamic) continue;

        address_t initArray = 0;
        address_t finiArray = 0;
        size_t initArraySz = 0;
        size_t finiArraySz = 0;
        ElfXX_Dyn *dyn = elfMap->getSectionReadPtr<ElfXX_Dyn *>(dynamic);
        auto n = dynamic->getSize() / sizeof(ElfXX_Dyn);
        for(size_t i = 0; i < n; i++, dyn++) {
            if(dyn->d_tag == 0) break;
            if(dyn->d_tag == DT_INIT || dyn->d_tag == DT_FINI) {
                auto f = CIter::spatial(module->getFunctionList())
                    ->findContaining(dyn->d_un.d_ptr);
                assert(f);
                markTreeAsUsed(f);
            }
            if(dyn->d_tag == DT_INIT_ARRAY) {
                initArray = dyn->d_un.d_ptr;
            }
            if(dyn->d_tag == DT_FINI_ARRAY) {
                finiArray = dyn->d_un.d_ptr;
            }
            if(dyn->d_tag == DT_INIT_ARRAYSZ) {
                initArraySz = dyn->d_un.d_val;
            }
            if(dyn->d_tag == DT_FINI_ARRAYSZ) {
                finiArraySz = dyn->d_un.d_val;
            }
        }

        useFromPointerArray(initArray, initArraySz, module);
        useFromPointerArray(finiArray, finiArraySz, module);
    }
}

void DebloatPass::useFromPointerArray(address_t start, size_t size,
    Module *module) {

    if(start == 0 || size == 0) return;

    // since this is dynamic, all the pointers in this array should have
    // a relocation (so don't read the value)

    auto relocList = module->getElfSpace()->getRelocList();
    if(!relocList) return;

    for(size_t sz = 0; sz < size; sz += sizeof(address_t)) {
        auto r = relocList->find(start + sz);
        Function *f = nullptr;
        if(auto addr = r->getAddend()) {
            f = CIter::spatial(module->getFunctionList())
                ->findContaining(addr);
        }
        else if(auto sym = r->getSymbol()) {
            f = CIter::spatial(module->getFunctionList())
                ->findContaining(sym->getAddress());
        }
        assert(f);
        markTreeAsUsed(f);
    }
}

void DebloatPass::useFromEntry() {
    auto entry = dynamic_cast<Function *>(program->getEntryPoint());
    assert(entry);
    markTreeAsUsed(entry);
}

void DebloatPass::useFromIndirectCallee() {
    IndirectCalleeList indirectCallees(program);
    for(auto f : indirectCallees.getList()) {
        markTreeAsUsed(f);
    }
}

void DebloatPass::useFromCodeLinks() {
    for(auto module : CIter::children(program)) {
        for(auto function : CIter::functions(module)) {
            for(auto block : CIter::children(function)) {
                for(auto instr : CIter::children(block)) {
                    if(auto link = instr->getSemantic()->getLink()) {
                        if(auto f = dynamic_cast<Function *>(
                            &*link->getTarget())) {

                            markTreeAsUsed(f);
                        }
                        else if(auto i = dynamic_cast<Instruction *>(
                            &*link->getTarget())) {

                            auto f = dynamic_cast<Function *>(
                                i->getParent()->getParent());
                            assert(f);
                            markTreeAsUsed(f);
                        }
                        else if(auto pl = dynamic_cast<PLTLink *>(link)) {
                            if(auto f = dynamic_cast<Function *>(
                                pl->getPLTTrampoline()->getTarget())) {

                                markTreeAsUsed(f);
                            }
                        }
                    }
                }
            }
        }
    }
}

void DebloatPass::useFromSpecialName() {
    for(auto module : CIter::children(program)) {
        for(auto function : CIter::functions(module)) {
            if(function->hasName("_start2")){
                markTreeAsUsed(function);
            }
            else if(function->hasName("ifunc_resolver")){
                markTreeAsUsed(function);
            }
            else if(function->hasName("egalito_runtime_init")){
                markTreeAsUsed(function);
            }
            if(isFeatureEnabled("EGALITO_USE_GS")) {
                if(function->hasName("egalito_pthread_create")
                    || function->hasName("egalito_sigaction")
                    || function->hasName("egalito_signal_handler")){

                    markTreeAsUsed(function);
                }
                else if(function->hasName("egalito_jit_gs_setup_thread")){
                    markTreeAsUsed(function);
                }
                else if(function->hasName("egalito_hook_jit_fixup")
                    || function->hasName("egalito_hook_jit_fixup_return")
                    || function->hasName("egalito_hook_jit_reset_on_syscall")) {

                    markTreeAsUsed(function);
                }
                else if(function->hasName("egalito_hook_after_clone_syscall")){
                    markTreeAsUsed(function);
                }
            }
        }
    }
}

void DebloatPass::markTreeAsUsed(Function *root) {
    //TemporaryLogLevel tll("pass", 10, root->hasName("type_midword");

    auto it = usedList.find(root);
    if(it != usedList.end()) return;

    Preorder order(&graph);

    auto id = graph.getNode(root)->getID();
    order.gen(id);

    for(auto n : order.get()[0]) {
        usedList.insert(graph.getFunction(n));
    }
}
