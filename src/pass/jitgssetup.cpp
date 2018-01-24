#include <sys/mman.h>
#include <cctype>
#include <cstring>
#include <cassert>
#include "config.h"
#include "jitgssetup.h"
#include "analysis/jumptable.h"
#include "chunk/tls.h"
#include "conductor/conductor.h"
#include "instr/semantic.h"
#include "instr/linked-x86_64.h"
#include "operation/find2.h"
#include "log/log.h"
#include "log/temp.h"
#include "cminus/print.h"

#ifndef JIT_RESET_THRESHOLD
#define JIT_RESET_THRESHOLD 1
#endif

extern "C"
void egalito_jit_gs_setup() {
    auto base = mmap(NULL, JIT_TABLE_SIZE, PROT_READ|PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    EgalitoTLS::setJITAddressTable(base);
    EgalitoTLS::setJITResetThreshold(JIT_RESET_THRESHOLD);

    auto gsTable = EgalitoTLS::getGSTable();
    for(auto entry : CIter::children(gsTable)) {
        auto target = entry->getTarget();
        if(dynamic_cast<AbsolutePosition *>(target->getPosition())) {
            target->setPositionIndex(Chunk::POSITION_JIT_GS);
        }
    }
}

void JitGSSetup::visit(Program *program) {
    makeHardwiredGSEntries(program->getEgalito());
    makeResolverGSEntries(program->getEgalito());
    makeSupportGSEntries(program);

    makeRequiredEntries();

    gsTable->finishReservation();
}

void JitGSSetup::makeHardwiredGSEntries(Module *egalito) {
    const auto reserved = {
        "egalito_hook_jit_fixup",           // hardcoded as gs@[0]
        "egalito_hook_jit_fixup_return",    // hardcoded as gs@[1]
        "egalito_hook_jit_reset_on_syscall",// hardcoded as gs@[2]
        "egalito_signal_handler",           // hardcoded as gs@[3]
    };
    for(auto name : reserved) {
        makeResolvedEntry(name, egalito);
    }
}

void JitGSSetup::makeResolverGSEntries(Module *egalito) {
    // matches any class that starts with
    const auto resolverClasses = {
#if 0
        //"ManageGS",
        //"ChunkFind2",
        "GSTable",
        //"GSTableEntry",
        //"GSTableLink",
        "Generator",
        "SandboxImplI13MemoryBacking",
        "MemoryBacking",
        "InstrWriterCString",
        //"ChunkMutator",
        //"Instruction",
        "AbsolutePosition",
        "AbsoluteOffsetPosition",
        "Position",
        //"InstructionStorage",
        //"IsolatedInstruction",
        //"ControlFlowInstruction",
        //"IndirectCallInstruction",
        //"IndirectJumpInstruction",
        //"LinkedInstruction",
        //"ReturnInstruction",
        "PLTList",
        "PLTTrampoline",
        //"DistanceLink",
        //"MarkerLink",
        //"SectionEndMarker",
        //"PLTLink",
        "OffsetLink",
        "ChunkCache",

        "DualSandbox",
        "WatermarkAllocator",

        //"EgalitoTLS",

        // for JIT'ting libegalito ctors
        "STLIterator",
#endif

        // for profiling
        "EgalitoTiming",
    };
    for(auto name : resolverClasses) {
        makeResolvedEntryForClass(name, egalito);
    }

    const auto resolvers = {
        //"egalito_jit_gs_fixup",
        //"egalito_jit_gs_init",
        //"egalito_jit_gs_reset",
        "_start2",
        "egalito_hook_after_clone_syscall",
        //"egalito_jit_gs_setup_thread",
        //"ifunc_resolver",
        //"ifunc_select",
        //"_ZNK9IFuncList6getForEm",

        "_ZNK22AbsoluteOffsetPosition3getEv",
        "_ZNK16AbsolutePosition3getEv",
        "_ZN16AbsolutePosition3setEm",
        "_ZNK22ChunkPositionDecoratorI9ChunkImplE11getPositionEv",
        "_ZNK9ChunkImpl10getAddressEv",
        //"_ZNK14DataOffsetLink16getTargetAddressEv",
        "_ZN11DualSandboxI11SandboxImplI13MemoryBacking18WatermarkAllocatorIS1_EEE8allocateEm",
        "_ZNK11GSTableLink16getTargetAddressEv",
        //"_ZNK11Instruction7getSizeEv",
        //"_ZN17LinkedInstruction6acceptEP18InstructionVisitor",
        "_ZNK14OffsetPosition3getEv",
        "_ZNK8Position13getGenerationEv",
        "_ZNK8Position13setGenerationEi",
        //"_ZN18InstrWriterCString5visitEP17LinkedInstruction",


        //"_ZNK9ChunkImpl10getAddressEv",
        //"_ZN13ChunkListImplI8FunctionE13createSpatialEv",
        //"_ZN9Emulation24function_not_implementedEv",
        //"_ZNSt8_Rb_treeImSt4pairIKmP8FunctionESt10_Select1stIS4_ESt4lessImESaIS4_EE29_M_get_insert_hint_unique_posESt23_Rb_tree_const_iteratorIS4_ERS1_",
        //"_ZNSt8_Rb_treeImSt4pairIKmP8FunctionESt10_Select1stIS4_ESt4lessImESaIS4_EE24_M_get_insert_unique_posERS1_",
        //"_ZNK9ChunkImpl8getRangeEv",
        //"_ZNK21ComputedSizeDecoratorI22ChunkPositionDecoratorI9ChunkImplEE7getSizeEv",
        //"_ZNK5Range8containsEm",
        //"_ZN13ChunkListImplI12GSTableEntryE3addEPS0_",
        //"_ZNSt8_Rb_treeIP5ChunkSt4pairIKS1_P12GSTableEntryESt10_Select1stIS6_ESt4lessIS1_ESaIS6_EE29_M_get_insert_hint_unique_posESt23_Rb_tree_const_iteratorIS6_ERS3_",
        //"_ZN12MakeSemantic13getDispOffsetEP8Assemblyi",
        //"_ZNK10NormalLink16getTargetAddressEv",
        //"_ZN18InstructionVisitor5visitEP23IndirectCallInstruction",
        //"_ZN18InstructionVisitor5visitEP17ReturnInstruction",
        //"_ZN12MakeSemantic25determineDisplacementSizeEP8Assemblyi",

        // for JIT'ting libegalito ctors
        //"_ZNK18ChildListDecoratorI21ComputedSizeDecoratorI22ChunkPositionDecoratorI9ChunkImplEE5BlockE11getChildrenEv",
        //"_ZN13ChunkListImplI5BlockE15genericIterableEv",
        //"_ZN14OffsetPosition11recalculateEv",
        //"_ZNK18ChildListDecoratorI21ComputedSizeDecoratorI22ChunkPositionDecoratorI9ChunkImplEE11InstructionE11getChildrenEv",
        //"_ZN13ChunkListImplI11InstructionE15genericIterableEv",
        //"_ZNK9ChunkImpl9getParentEv",
        //"_ZNK9ChunkImpl11getChildrenEv",

        // for debugging & profiling
        //"egalito_printf",
        //"egalito_vfprintf",
        //"write_decimal",
        //"write_hex",
        //"write_string",

#ifndef RELEASE_BUILD
        // for debugging
        //"_ZNK8Function7getNameB5cxx11Ev",
        //"_ZNK13PLTTrampoline7getNameB5cxx11Ev",
        //"_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE12_M_constructIPcEEvT_S7_St20forward_iterator_tag.isra.23",
        //"_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE12_M_constructIPcEEvT_S7_St20forward_iterator_tag.isra.29",
        "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE12_M_constructIPcEEvT_S7_St20forward_iterator_tag.isra.66",
        //"_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE12_M_constructIPcEEvT_S7_St20forward_iterator_tag.isra.72",
        //"_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE12_M_constructIPKcEEvT_S8_St20forward_iterator_tag.isra.323",
#endif
    };
    for(auto name : resolvers) {
        makeResolvedEntry(name, egalito);
    }
}

void JitGSSetup::makeSupportGSEntries(Program *program) {
    for(auto module : CIter::children(program)) {
        if(module->getName() == "module-libc.so.6") {
            //makeResolvedEntry("write", module);
            //makeResolvedEntry("memcpy", module);
            //makeResolvedEntry("__memcpy_erms", module);
            //makeResolvedEntry("__memcpy_sse2_unaligned_erms", module);
            //makeResolvedEntry("__memcpy_ssse3_back", module);
            //makeResolvedEntry("__memcpy_avx512_unaligned_erms", module);
            //makeResolvedEntry("__memcpy_ssse3", module);
            //makeResolvedEntry("__memcpy_sse2_unaligned", module);
            //makeResolvedEntry("__memcpy_avx512_unaligned", module);
            //makeResolvedEntry("__memcpy_avx_unaligned_erms", module);
            //makeResolvedEntry("__memcpy_avx512_no_vzeroupper", module);
            //makeResolvedEntry("__memcpy_avx_unaligned", module);
            //makeResolvedEntry("malloc", module);
            //makeResolvedEntry("malloc_hook_ini", module);
            //makeResolvedEntry("ptmalloc_init.part.3", module);
            //makeResolvedEntry("_dl_addr", module);
            //makeResolvedEntry("malloc_consolidate", module);
            //makeResolvedEntry("malloc_init_state", module);
            //makeResolvedEntry("tcache_init.part.9", module);
            //makeResolvedEntry("_int_malloc", module);
            //makeResolvedEntry("sysmalloc", module);
            //makeResolvedEntry("print_and_abort", module);
            //makeResolvedEntry("__default_morecore", module);
            //makeResolvedEntry("sbrk", module);
            //makeResolvedEntry("brk", module);
            //makeResolvedEntry("mprotect", module);
            //makeResolvedEntry("mmap", module);
            //makeResolvedEntry("strlen", module);
            //makeResolvedEntry("__strlen_avx2", module);
            //makeResolvedEntry("__strlen_sse2", module);
            //makeResolvedEntry("memmove", module);
            //makeResolvedEntry("newlocale", module);
            //makeResolvedEntry("uselocale", module);
            //makeResolvedEntry("wctob", module);
            //makeResolvedEntry("btowc", module);
            //makeResolvedEntry("_dl_mcount_wrapper_check", module);
            //makeResolvedEntry("__gconv_btwoc_ascii", module);
            //makeResolvedEntry("wctype_l", module);
            //makeResolvedEntry("memcmp", module);
            //makeResolvedEntry("__memcmp_sse2", module);
            //makeResolvedEntry("__memcmp_avx2_movbe", module);
            //makeResolvedEntry("__memcmp_ssse3", module);
            //makeResolvedEntry("__memcmp_sse4_1", module);
            //makeResolvedEntry("strcmp", module);
            //makeResolvedEntry("__strcmp_sse2_unaligned", module);
            //makeResolvedEntry("__strcmp_ssse3", module);
            //makeResolvedEntry("__strcmp_sse2", module);
            //makeResolvedEntry("__strcmp_sse42", module);
            //makeResolvedEntry("free", module);
            //makeResolvedEntry("_int_free", module);
            //makeResolvedEntry("tcache_put", module);
            //makeResolvedEntry("tcache_get", module);
            //makeResolvedEntry("memset", module);
            //makeResolvedEntry("__memset_avx512_unaligned_erms", module);
            //makeResolvedEntry("__memset_erms", module);
            //makeResolvedEntry("__memset_avx512_unaligned", module);
            //makeResolvedEntry("__memset_avx2_unaligned_erms", module);
            //makeResolvedEntry("__memset_avx2_unaligned", module);
            //makeResolvedEntry("__memset_sse2_unaligned", module);
            //makeResolvedEntry("__memset_avx2_erms", module);
            //makeResolvedEntry("__memset_sse2_unaligned_erms", module);
            //makeResolvedEntry("__memset_avx512_erms", module);
            //makeResolvedEntry("__memset_avx512_no_vzeroupper", module);
            //makeResolvedEntry("arch_prctl", module);
            // spwaned thread
            //makeResolvedEntry("get_free_list", module);
            //makeResolvedEntry("arena_get2.part.8", module);
            //makeResolvedEntry("new_heap", module);
            //makeResolvedEntry("munmap", module);
            // JIT GS address table
            //makeResolvedEntry("explicit_bzero", module);
            // for profiling
            //makeResolvedEntry("clock_gettime", module);
            makeResolvedEntry("__syscall_clock_gettime", module);
        }
        else if(module->getName() == "module-libstdc++.so.6") {
            //makeResolvedEntry("__dynamic_cast", module);
            //makeResolvedEntry("_ZdlPv", module);
            //makeResolvedEntry("_Znwm", module);
            //makeResolvedEntry("_ZSt29_Rb_tree_insert_and_rebalancebPSt18_Rb_tree_node_baseS0_RS_", module);
            //makeResolvedEntry("_ZSt18_Rb_tree_decrementPSt18_Rb_tree_node_base", module);
            //makeResolvedEntry("_ZStL23local_Rb_tree_decrementPSt18_Rb_tree_node_base", module);
            //makeResolvedEntry("_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE10_M_replaceEmmPKcm", module);
            makeResolvedEntry("_ZNK10__cxxabiv117__class_type_info12__do_dyncastElNS0_10__sub_kindEPKS0_PKvS3_S5_RNS0_16__dyncast_resultE", module);
            makeResolvedEntry("_ZNK10__cxxabiv120__si_class_type_info12__do_dyncastElNS_17__class_type_info10__sub_kindEPKS1_PKvS4_S6_RNS1_16__dyncast_resultE", module);
            // for JIT'ting libegalito ctors
            //makeResolvedEntry("_ZdlPvm", module);

#ifndef RELEASE_BUILD
            // for debugging
            makeResolvedEntry("_ZNSt8ios_baseC1Ev", module);
            makeResolvedEntry("_ZNSt6localeC1Ev", module);
            makeResolvedEntry("_ZNSt6locale13_S_initializeEv", module);
            makeResolvedEntry("_ZNSt6locale18_S_initialize_onceEv", module);
            makeResolvedEntry("_ZNSt6locale5_ImplC2Em", module);
            makeResolvedEntry("_ZNSt6locale5facet13_S_get_c_nameEv", module);
            makeResolvedEntry("_ZNSt5ctypeIcEC1EPKtbm", module);
            makeResolvedEntry("_ZNSt6locale5facet15_S_get_c_localeEv", module);
            makeResolvedEntry("_ZNSt6locale5facet18_S_initialize_onceEv", module);
            makeResolvedEntry("_ZNSt6locale5facet18_S_create_c_localeERP15__locale_structPKcS2_", module);
            makeResolvedEntry("_ZNSt6locale5_Impl16_M_install_facetEPKNS_2idEPKNS_5facetE", module);
            makeResolvedEntry("_ZNKSt6locale2id5_M_idEv", module);
            makeResolvedEntry("_ZNSt7codecvtIcc11__mbstate_tEC2Em", module);
            makeResolvedEntry("_ZNSt7__cxx118numpunctIcE22_M_initialize_numpunctEP15__locale_struct", module);
            makeResolvedEntry("_ZNSt7__cxx1110moneypunctIcLb0EE24_M_initialize_moneypunctEP15__locale_structPKc", module);
            makeResolvedEntry("_ZNSt7__cxx1110moneypunctIcLb1EE24_M_initialize_moneypunctEP15__locale_structPKc", module);
            makeResolvedEntry("_ZNSt11__timepunctIcEC1EPSt17__timepunct_cacheIcEm", module);
            makeResolvedEntry("_ZNSt11__timepunctIcE23_M_initialize_timepunctEP15__locale_struct", module);
            makeResolvedEntry("_ZNSt7__cxx118messagesIcEC2Em", module);
            makeResolvedEntry("_ZNSt5ctypeIwEC1Em", module);
            makeResolvedEntry("_ZNSt5ctypeIwE19_M_initialize_ctypeEv", module);
            makeResolvedEntry("_ZNKSt5ctypeIwE19_M_convert_to_wmaskEt", module);
            makeResolvedEntry("_ZNSt7codecvtIwc11__mbstate_tEC2Em", module);
            makeResolvedEntry("_ZNSt7__cxx118numpunctIwE22_M_initialize_numpunctEP15__locale_struct", module);
            makeResolvedEntry("_ZNSt7__cxx1110moneypunctIwLb0EE24_M_initialize_moneypunctEP15__locale_structPKc", module);
            makeResolvedEntry("_ZNSt7__cxx1110moneypunctIwLb1EE24_M_initialize_moneypunctEP15__locale_structPKc", module);
            makeResolvedEntry("_ZNSt11__timepunctIwEC1EPSt17__timepunct_cacheIwEm", module);
            makeResolvedEntry("_ZNSt11__timepunctIwE23_M_initialize_timepunctEP15__locale_struct", module);
            makeResolvedEntry("_ZNSt7__cxx118messagesIwEC1Em", module);
            makeResolvedEntry("_ZNSt6locale5_Impl13_M_init_extraEPPNS_5facetE", module);
            makeResolvedEntry("_ZNSt8numpunctIcE22_M_initialize_numpunctEP15__locale_struct", module);
            makeResolvedEntry("_ZNSt10moneypunctIcLb0EE24_M_initialize_moneypunctEP15__locale_structPKc", module);
            makeResolvedEntry("_ZNSt10moneypunctIcLb1EE24_M_initialize_moneypunctEP15__locale_structPKc", module);
            makeResolvedEntry("_ZNSt8messagesIcEC1Em", module);
            makeResolvedEntry("_ZNSt8numpunctIwE22_M_initialize_numpunctEP15__locale_struct", module);
            makeResolvedEntry("_ZNSt10moneypunctIwLb0EE24_M_initialize_moneypunctEP15__locale_structPKc", module);
            makeResolvedEntry("_ZNSt10moneypunctIwLb1EE24_M_initialize_moneypunctEP15__locale_structPKc", module);
            makeResolvedEntry("_ZNSt8messagesIwEC2Em", module);
            makeResolvedEntry("_ZNSt9basic_iosIcSt11char_traitsIcEE4initEPSt15basic_streambufIcS1_E", module);
            makeResolvedEntry("_ZNSt8ios_base7_M_initEv", module);
            makeResolvedEntry("_ZNSt6localeaSERKS_", module);
            makeResolvedEntry("_ZNSt6localeD1Ev", module);
            makeResolvedEntry("_ZNSt9basic_iosIcSt11char_traitsIcEE15_M_cache_localeERKSt6locale", module);
            makeResolvedEntry("_ZSt9has_facetISt5ctypeIcEEbRKSt6locale", module);
            makeResolvedEntry("_ZNK10__cxxabiv121__vmi_class_type_info12__do_dyncastElNS_17__class_type_info10__sub_kindEPKS1_PKvS4_S6_RNS1_16__dyncast_resultE", module);
            makeResolvedEntry("_ZSt9use_facetISt5ctypeIcEERKT_RKSt6locale", module);
            makeResolvedEntry("_ZSt9has_facetISt7num_putIcSt19ostreambuf_iteratorIcSt11char_traitsIcEEEEbRKSt6locale", module);
            makeResolvedEntry("_ZSt9use_facetISt7num_putIcSt19ostreambuf_iteratorIcSt11char_traitsIcEEEERKT_RKSt6locale", module);
            makeResolvedEntry("_ZSt9has_facetISt7num_getIcSt19istreambuf_iteratorIcSt11char_traitsIcEEEEbRKSt6locale", module);
            makeResolvedEntry("_ZSt9use_facetISt7num_getIcSt19istreambuf_iteratorIcSt11char_traitsIcEEEERKT_RKSt6locale", module);
            makeResolvedEntry("_ZSt16__ostream_insertIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_PKS3_l", module);
            makeResolvedEntry("_ZNSo6sentryC1ERSo", module);
            makeResolvedEntry("_ZNSt15basic_streambufIcSt11char_traitsIcEE6xsputnEPKcl", module);
            makeResolvedEntry("_ZNSt7__cxx1115basic_stringbufIcSt11char_traitsIcESaIcEE8overflowEi", module);
            makeResolvedEntry("_ZNSt7__cxx1115basic_stringbufIcSt11char_traitsIcESaIcEE8_M_pbumpEPcS5_l", module);
            makeResolvedEntry("_ZNSo6sentryD2Ev", module);
            makeResolvedEntry("_ZNSo9_M_insertImEERSoT_", module);
            makeResolvedEntry("_ZNKSt5ctypeIcE13_M_widen_initEv", module);
            makeResolvedEntry("_ZNKSt7num_putIcSt19ostreambuf_iteratorIcSt11char_traitsIcEEE6do_putES3_RSt8ios_basecm", module);
            makeResolvedEntry("_ZNKSt7num_putIcSt19ostreambuf_iteratorIcSt11char_traitsIcEEE13_M_insert_intImEES3_S3_RSt8ios_basecT_", module);
            makeResolvedEntry("_ZNKSt11__use_cacheISt16__numpunct_cacheIcEEclERKSt6locale", module);
            makeResolvedEntry("_ZSt13__int_to_charIcmEiPT_T0_PKS0_St13_Ios_Fmtflagsb", module);
            makeResolvedEntry("_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE9_M_assignERKS4_", module);
            makeResolvedEntry("_ZNSt8ios_baseD2Ev", module);
            makeResolvedEntry("_ZNSt8ios_base17_M_call_callbacksENS_5eventE", module);
            makeResolvedEntry("_ZNSt8ios_base20_M_dispose_callbacksEv", module);
            makeResolvedEntry("_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE9_M_createERmm", module);
            makeResolvedEntry("_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE7compareEPKc", module);
            makeResolvedEntry("_ZNK10__cxxabiv117__class_type_info11__do_upcastEPKS0_PPv", module);
            makeResolvedEntry("_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE9_M_mutateEmmPKcm", module);
            makeResolvedEntry("_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE9_M_appendEPKcm", module);
#endif

            // for profiling
            //makeResolvedEntry("_ZNSt6chrono3_V212system_clock3nowEv", module);
        }
#if 0
        else if(module->getName() == "module-libdistorm3.so") {
            makeResolvedEntry("distorm_decompose64", module);
            makeResolvedEntry("decode_internal", module);
            makeResolvedEntry("prefixes_is_valid", module);
            makeResolvedEntry("prefixes_decode", module);
            makeResolvedEntry("prefixes_ignore", module);
            makeResolvedEntry("inst_lookup", module);
            makeResolvedEntry("inst_lookup_prefixed", module);
            makeResolvedEntry("operands_extract", module);
            makeResolvedEntry("operands_extract_modrm", module);
            makeResolvedEntry("prefixes_use_segment", module);
            makeResolvedEntry("prefixes_set_unused_mask", module);
        }
#endif
#if 0
        else if(module->getName() == "module-libpthread.so.0") {
            makeResolvedEntry("write", module);
            makeResolvedEntry("pthread_once", module);
            makeResolvedEntry("__pthread_once_slow", module);
            makeResolvedEntry("_pthread_cleanup_push", module);
            makeResolvedEntry("_pthread_cleanup_pop", module);
            makeResolvedEntry("__pthread_enable_asynccancel", module);
            makeResolvedEntry("__pthread_disable_asynccancel", module);
        }
#endif
    }
#if 0
    makeResolvedEntryForPLT("memcpy@plt", program);
    makeResolvedEntryForPLT("_dl_find_dso_for_object@plt", program);
    makeResolvedEntryForPLT("distorm_decompose64@plt", program);
    makeResolvedEntryForPLT("strlen@plt", program);
    makeResolvedEntryForPLT("memmove@plt", program);
    makeResolvedEntryForPLT("memcmp@plt", program);
    makeResolvedEntryForPLT("strcmp@plt", program);
    makeResolvedEntryForPLT("memset@plt", program);
#endif
}

void JitGSSetup::makeResolvedEntry(const char *name, Module *module) {
    bool found = false;
    for(auto f : CIter::functions(module)) {
        if(f->hasName(name)) {
            makeResolvedEntryForFunction(f);
            found = true;
        }
    }
    assert(found);
}

void JitGSSetup::makeResolvedEntryForClass(const char *name, Module *module) {
    bool found = false;
    for(auto f : CIter::functions(module)) {
        auto fname = f->getName();
        const char *cname = fname.c_str();
        if(cname[0] == '_' && cname[1] == 'Z') {
            const char *p = cname + 2;
            while(!isdigit(*p)) ++p;
            while(isdigit(*p)) ++p;
            if(std::strncmp(p, name, strlen(name)) == 0) {
                makeResolvedEntryForFunction(f);
                found = true;
            }
        }
    }
    assert(found);
}

void JitGSSetup::makeResolvedEntryForFunction(Function *function) {
    // we can't do anything about libegalito's exception in JIT code
    // and ditto for any other error cases
    if(function->hasName("_Unwind_Resume")
        || function->hasName("_Unwind_RaiseException")
        || function->hasName("_Unwind_Resume_or_Rethrow")
        || function->hasName("__cxa_throw")
        || function->hasName("__cxa_throw_bad_array_new_length")
        || function->hasName("__cxa_allocate_exception")
        || function->hasName("__cxa_call_unexpected")
        || function->hasName("__cxa_bad_cast")
        || function->hasName("__cxa_begin_catch")
        || function->hasName("__cxa_rethrow")
        || function->hasName("__cxa_end_catch")
        || function->hasName("_ZSt18uncaught_exceptionv")
        || function->hasName("_ZSt19__throw_ios_failurePKc")
        || function->hasName("_ZSt19__throw_logic_errorPKc")
        || function->hasName("_ZSt20__throw_length_errorPKc")
        || function->hasName("_ZSt21__throw_runtime_errorPKc")
        || function->hasName("_ZSt24__throw_out_of_range_fmtPKcz")
        || function->hasName("_ZSt16__throw_bad_castv")
        || function->hasName("_ZNSt9bad_allocD2Ev")
        || function->hasName("_ZN9__gnu_cxx20recursive_init_errorD2Ev")
        || function->hasName("_ZN9__gnu_cxx30__throw_concurrence_lock_errorEv")
        || function->hasName("_ZN9__gnu_cxx32__throw_concurrence_unlock_errorEv")
        || function->hasName("_ZN9__gnu_cxx26__concurrence_unlock_errorD1Ev")
        || function->hasName("_ZN9__gnu_cxx26__throw_insufficient_spaceEPKcS1_")
        || function->hasName("_ZSt13get_terminatev")
        || function->hasName("_ZN10__cxxabiv111__terminateEPFvvE")
        || function->hasName("_ZNSt9exceptionD1Ev")
        || function->hasName("unwind_cleanup")
        || function->hasName("unwind_stop")
        || function->hasName("_Unwind_ForcedUnwind")
        || function->hasName("__assert_fail")
        || function->hasName("__stack_chk_fail")
        || function->hasName("__malloc_assert")
        || function->hasName("malloc_printerr")
        || function->hasName("__libc_fatal")
        || function->hasName("__libc_message")
        || function->hasName("abort")
        || function->hasName("__pthread_unwind")
    ) {
        return;
    }

    if(function->hasName("__libc_dlopen_mode")
        || function->hasName("__libc_dlsym")
        || function->hasName("_dl_vdso_vsym")
        || function->hasName("pthread_key_create")
    ) {

        return;
    }

    //egalito_printf("making entry for %s\n", function->getName().c_str());
    gsTable->makeReservedEntryFor(function);
    auto module = dynamic_cast<Module *>(function->getParent()->getParent());
    for(auto jt : CIter::children(module->getJumpTableList())) {
        auto d = jt->getDescriptor();
        if(d->getFunction() == function) {
            for(auto je : CIter::children(jt)) {
                if(auto link = dynamic_cast<NormalLink *>(je->getLink())) {
                    gsTable->makeReservedEntryFor(link->getTarget());
                }
            }
        }
    }
}

#if 0
void JitGSSetup::makeResolvedEntryForPLT(std::string name, Program *program) {
    bool found = false;
    for(auto module : CIter::children(program)) {
        for(auto plt : CIter::children(module->getPLTList())) {
            if(plt->getName() == name) {
                found = true;
                gsTable->makeReservedEntryFor(plt);
                if(auto target = plt->getTarget()) {
                    gsTable->makeReservedEntryFor(target);
                }
                else {
                    LOG(9, "Unresolved PLT entry to ["
                        << plt->getExternalSymbol()->getName() << "]");
                }
                break;
            }
        }
    }
    assert(found);
}
#endif

void JitGSSetup::makeResolvedEntryForPLT(PLTTrampoline *plt) {
    if(!plt->getTarget()) return;

    //egalito_printf("making PLT entry for %s\n", plt->getName().c_str());
    gsTable->makeReservedEntryFor(plt);
    if(auto target = plt->getTarget()) {
        gsTable->makeReservedEntryFor(target);
    }
}

void JitGSSetup::makeRequiredEntries() {
    //TemporaryLogLevel tll("pass", 10);

    size_t count;
    do {
        count = gsTable->getChildren()->getIterable()->getCount();
        LOG(10, "reserved entries in GS table now = " << count);
        std::cout.flush();
        for(size_t i = 0; i < count; i++) {
            auto entry = gsTable->getAtIndex(i);
            auto target = entry->getTarget();
            if(dynamic_cast<Instruction *>(target)) continue;

            makeRequiredEntriesFor(target);
        }
    } while(count != gsTable->getChildren()->getIterable()->getCount());
}

void JitGSSetup::makeRequiredEntriesFor(Chunk *chunk) {
    LOG(10, "making required entries for " << chunk->getName());
    //egalito_printf("making required entries for %s\n", chunk->getName().c_str());
    for(auto b : chunk->getChildren()->genericIterable()) {
        auto block = dynamic_cast<Block *>(b);
        for(auto i : CIter::children(block)) {
            if(auto link = i->getSemantic()->getLink()) {
                Chunk *target = nullptr;
                if(auto dlink = dynamic_cast<DataOffsetLink *>(link)) {
                    auto sec = dynamic_cast<DataSection *>(dlink->getTarget());
                    //!!! replace this with DataSection::findVariable() later
                    auto var
                        = CIter::spatial(sec)->find(dlink->getTargetAddress());
                    if(var) {
                        auto link = dynamic_cast<NormalLink *>(var->getDest());
                        if(link) {
                            target = link->getTarget();
                        }
                    }
                }
                else {
                    target = link->getTarget();
                }
                if(target) {
                    if(auto f = dynamic_cast<Function *>(target)) {
                        LOG(10, "    needs " << target->getName());
                        //egalito_printf("    needs %s\n", target->getName().c_str());
                        makeResolvedEntryForFunction(f);
                    }
                    else if (auto plt = dynamic_cast<PLTTrampoline *>(target)) {
                        LOG(10, "    needs " << target->getName());
                        //egalito_printf("    needs %s\n", target->getName().c_str());
                        makeResolvedEntryForPLT(plt);
                    }
                }
            }
        }
    }
}

