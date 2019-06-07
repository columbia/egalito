#include <cassert>
#include "collapseplt.h"
#include "chunk/link.h"
#include "chunk/plt.h"
#include "conductor/conductor.h"
#include "instr/semantic.h"
#include "operation/find2.h"
#include "log/log.h"
#include "log/temp.h"

// only supports libc and libm for now
static Function *findFunction(Conductor *conductor, const char *name) {
    //ChunkFind2() doesn't work here for now
    //return ChunkFind2(conductor).findFunction(#target);

    for(auto f : CIter::functions(conductor->getProgram()->getLibc())) {
        if(!f->isIFunc() && f->hasName(name)) {
            LOG(12, "found ifunc target [" << f->getName()
                << "] for " << name);
            return f;
        }
    }
    for(auto module : CIter::modules(conductor->getProgram())) {
        if(module->getName() == "module-libm.so.6") {
            for(auto f : CIter::functions(module)) {
                if(!f->isIFunc() && f->hasName(name)) {
                    LOG(12, "found ifunc target [" << f->getName()
                        << "] for " << name);
                    return f;
                }
            }
        }
    }
    return nullptr;
}

CollapsePLTPass::CollapsePLTPass(Conductor *conductor)
    : conductor(conductor) {

    //TemporaryLogLevel tll("pass", 20);
    Function *function = nullptr;
#if 0
#define KNOWN_IFUNC_ENTRY(name, target) \
    function = ChunkFind2(conductor).findFunction(#target); \
    ifuncMap.emplace(#name, function);
#else
#define KNOWN_IFUNC_ENTRY(name, target) \
    function = findFunction(conductor, #target); \
    if(function) ifuncMap.emplace(#name, function);
#endif

#include "../dep/ifunc/ifunc.h"

#undef KNOWN_IFUNC_ENTRY

    for(auto pair : ifuncMap) {
        assert(pair.second);
        LOG(10, "IFunc " << pair.first << " -> " << pair.second->getName());
    }
}

void CollapsePLTPass::visit(Module *module) {
    //TemporaryLogLevel tll("pass", 20);

    recurse(module);
    recurse(module->getDataRegionList());
}

void CollapsePLTPass::visit(Instruction *instr) {
    if(auto pltLink
        = dynamic_cast<PLTLink *>(instr->getSemantic()->getLink())) {

        auto trampoline = pltLink->getPLTTrampoline();

        if(trampoline->isIFunc()) {
            auto name = trampoline->getExternalSymbol()->getName();
            auto it = ifuncMap.find(name);
            if(it != ifuncMap.end()) {
                LOG(10, "resolving IFunc " << name
                    << " as " << it->second->getName());
                instr->getSemantic()->setLink(
                    new NormalLink(it->second, Link::SCOPE_EXTERNAL_JUMP));
                delete pltLink;
            }
            else {
                LOG(10, "IFunc " << name << " will be resolved at runtime");
            }
            return;  // we don't handle this yet
        }

        if(auto target = trampoline->getTarget()) {
            instr->getSemantic()->setLink(
                new NormalLink(target, Link::SCOPE_EXTERNAL_JUMP));
            delete pltLink;
        }
        else {
            assert(trampoline->getExternalSymbol());
            LOG(9, "Unresolved PLT entry from " << instr->getName()
                << " to [" << trampoline->getExternalSymbol()->getName() << "]");
        }
    }
}

// see note in ifunclazy.h
void CollapsePLTPass::visit(DataSection *section) {
    for(auto var : CIter::children(section)) {
        auto dest = var->getDest();
        if(!dest) continue;

        if(auto f = dynamic_cast<Function *>(dest->getTarget())) {
            auto it = ifuncMap.find(f->getName());
            if(it != ifuncMap.end()) {
                LOG(10, "redirecting IFUNC " << f->getName()
                    << " to " << it->second->getName());
                auto link
                    = new NormalLink(it->second, Link::SCOPE_EXTERNAL_JUMP);
                var->setDest(link);
                delete dest;
            }
        }
    }
}
