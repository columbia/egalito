#include <cassert>
#include "jitgssetup.h"
#include "conductor/conductor.h"
#include "operation/find2.h"
#include "log/log.h"

void JitGSSetup::visit(Program *program) {
    makeResolverGSEntries(program->getEgalito());
    makeSupportGSEntries(program);
}

void JitGSSetup::makeResolverGSEntries(Module *egalito) {
    const auto resolvers = {
        "egalito_jit_gs_fixup",
        "_ZN7GSTable13offsetToIndexEj",
        "_ZN8ManageGS7resolveEP7GSTablej",
        "_ZN9Generator21copyFunctionToSandboxEP8FunctionP7Sandbox",
        "_ZN8ManageGS8setEntryEP7GSTablejm",
        "_ZN10ChunkFind2C1EP9Conductor",
        "_ZN10ChunkFind222findFunctionContainingEm",
        "_ZN7GSTable10getAtIndexEj",
        "_ZN12GSTableEntry15setLazyResolverEP5Chunk",
        "_ZNK9ChunkImpl10getAddressEv",
        "_ZNK22ChunkPositionDecoratorI9ChunkImplE11getPositionEv",
        "_ZNK16AbsolutePosition3getEv",
        "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE12_M_constructIPKcEEvT_S8_St20forward_iterator_tag.isra.249",
        // for debugging
        "egalito_printf",
        "egalito_vfprintf",
        "write_decimal",
        "write_hex",
        "write_string",
        "_ZNK8Function7getNameB5cxx11Ev",
        "ifunc_resolver",
        "ifunc_resolve",
        "_ZNK9IFuncList6getForEm"
    };
    for(auto name : resolvers) {
        makeResolvedEntry(name, egalito);
    }
}

void JitGSSetup::makeSupportGSEntries(Program *program) {
    for(auto module : CIter::children(program)) {
        if(module->getName() == "module-libc.so.6") {
            makeResolvedEntry("write", module);
            makeResolvedEntry("memcpy", module);
        }
        else if(module->getName() == "module-libstdcc++.so.6") {
            makeResolvedEntry("__dynamic_cast", module);
            makeResolvedEntry("_ZdlPv", module);
        }
    }
    makeResolvedEntryForPLT("memcpy@plt", program);
}

void JitGSSetup::makeResolvedEntry(const char *name, Module *module) {
    auto f = ChunkFind2(conductor).findFunctionInModule(name, module);
    assert(f);
    gsTable->makeEntryFor(f, true);
}

void JitGSSetup::makeResolvedEntryForPLT(std::string name, Program *program) {
    bool found = false;
    for(auto module : CIter::children(program)) {
        for(auto plt : CIter::children(module->getPLTList())) {
            if(plt->getName() == name) {
                found = true;
                gsTable->makeEntryFor(plt, true);
                break;
            }
        }
    }
    assert(found);
}
