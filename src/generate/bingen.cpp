#include <sys/mman.h>
#include <cstring>
#include <algorithm>

#include "bingen.h"
#include "chunk/concrete.h"
#include "conductor/conductor.h"
#include "conductor/setup.h"
#include "elf/elfspace.h"
#include "instr/semantic.h"
#include "instr/writer.h"
#include "load/segmap.h"
#include "operation/find.h"
#include "operation/mutator.h"
#include "pass/fixdataregions.h"
#include "pass/instrumentcalls.h"
#include "pass/switchcontext.h"
#include "pass/relocheck.h"
#include "snippet/hook.h"
#include "snippet/logfunction.h"

#include "log/log.h"
#include "log/temp.h"
#include "chunk/dump.h"

#define TARGET_IS_MAGENTA   1

#define ROUND_DOWN(x)       ((x) & ~0xfff)
#define ROUND_UP(x)         (((x) + 0xfff) & ~0xfff)
#define ROUND_UP_BY(x, y)   (((x) + (y) - 1) & ~((y) - 1))

static std::vector<Function *> makeSortedFunctionList(Module *module) {
    std::vector<Function *> list;
    for(auto func : CIter::functions(module)) {
        list.push_back(func);
    }
    std::sort(list.begin(), list.end(),
        [](Function *a, Function *b) {
            return a->getAddress() < b->getAddress();
        });
    return list;
}

BinGen::BinGen(ConductorSetup *setup, const char *filename)
    : setup(setup), mainModule(nullptr), addon(nullptr),
      fs(filename, std::ios::out | std::ios::binary) {

    mainModule = setup->getConductor()->getProgram()->getMain();
    moduleList.push_back(mainModule);
    for(auto module : CIter::children(setup->getConductor()->getProgram())) {
        if(module->getName() == "module-(addon)") {
            addon = module;
            moduleList.push_back(addon);
            break;
        }
    }
}

BinGen::~BinGen() {
    fs.close();
}

int BinGen::generate() {
    changeMapAddress(mainModule, 0xa0000000);
    SegMap::mapAllSegments(setup);

#if 0
    RelocDataPass relocData(setup->getConductor());
    setup->getConductor()->getProgram()->accept(&relocData);
#endif

    ReloCheckPass checker;
    setup->getConductor()->getProgram()->accept(&checker);

    applyAdditionalTransform();

    endOfCode = reassignFunctionAddress();

    interleaveData();

    fixMarkers();

    FixDataRegionsPass fixDataRegions;
    setup->getConductor()->getProgram()->accept(&fixDataRegions);

    address_t pos = makeImageBox();
    writeOut(pos);

    setup->getConductor()->writeDebugElf("bin-symbols.elf");


    LOG(1, "<image layout>");
    LOG(1, "code: " << pos << " - " << endOfCode);
    LOG(1, "rodata: - " << endOfRoData);
    LOG(1, "data:   - " << endOfData);
    LOG(1, "bss:    - " << endOfBss);

    ChunkDumper dumper;
    for(auto region : CIter::regions(mainModule)) {
        region->accept(&dumper);
    }
    if(addon) {
        for(auto region : CIter::regions(addon)) {
            region->accept(&dumper);
        }
    }
    LOG(0, "entry point at 0x" << std::hex << setup->getEntryPoint());

    return 0;
}

void BinGen::applyAdditionalTransform() {
    addCallLogging();

#if !TARGET_IS_MAGENTA
    // this isn't necessary for real firmware which clears bss by itself
    addBssClear();
#endif

    dePLT();
}

address_t BinGen::reassignFunctionAddress() {
    auto list = makeSortedFunctionList(mainModule);

    // we have to reassign address here because size could have been
    // changed due to instrumentation
    auto address = list.front()->getAddress();
    startOfCode = address;
    for(auto func : list) {
        // if this heuristics to find out alignment fails, we need to make a
        // list of functions with special alignment (e.g. vector table)

        auto org = func->getAddress();
        if(address != ROUND_UP_BY(address, org & -org)) {
            LOG(1, "rouding up " << address << " by " << (org & -org));
        }
        address = ROUND_UP_BY(address, org & -org);
        LOG(1, func->getName() << " : " << std::hex
            << func->getAddress() << " -> " << address
            << " - " << (address + func->getSize()));

        ChunkMutator(func).setPosition(address);
        address += func->getSize();
    }

    if(addon) {
        list = makeSortedFunctionList(addon);
        for(auto func : list) {
            LOG(10, func->getName() << " : "
                << func->getAddress() << " -> " << address);
            ChunkMutator(func).setPosition(address);
            address += func->getSize();
        }
    }

    return list.back()->getAddress() + list.back()->getSize();
}

void BinGen::addCallLogging() {
#if defined(ARCH_AARCH64)
    if(!addon) return;

    auto funcEntry = CIter::named(addon->getFunctionList())
        ->find("egalito_log_function_entry");
    if(!funcEntry) return;

    auto funcExit = CIter::named(addon->getFunctionList())
        ->find("egalito_log_function_exit");
    if(!funcExit) return;

    auto epilogue = CIter::named(addon->getFunctionList())
        ->find("egalito_dump_logs");
    if(!epilogue) return;

#if !TARGET_IS_MAGENTA
    #define MAIN_FUNCTION_NAME  "main"
#else
    #define MAIN_FUNCTION_NAME  "kernel_init"
#endif

    auto mainFunc
        = CIter::named(mainModule->getFunctionList())->find(MAIN_FUNCTION_NAME);
    if(!mainFunc) return;

    SwitchContextPass switcher;
    funcEntry->accept(&switcher);
    funcExit->accept(&switcher);
    epilogue->accept(&switcher);

    set_function_entry_hook(egalito_log_function_entry);
    set_function_exit_hook(egalito_log_function_exit);

    InstrumentCallsPass instrument;
    instrument.setEntryAdvice(funcEntry);
    instrument.setExitAdvice(funcExit);
    instrument.setPredicate([](Function *function) {
#if !TARGET_IS_MAGENTA
        if(function->hasName("_start")) return false;
        if(function->hasName("__start_ram1")) return false;
        if(function->hasName("__start_master")) return false;
        auto firstB = function->getChildren()->getIterable()->get(0);
        auto firstI = firstB->getChildren()->getIterable()->get(0);
        auto semantic = firstI->getSemantic();
        if(dynamic_cast<LiteralInstruction *>(semantic)) return false;
        return true;
#else
        if(function->hasName("kernel_init")) return true;
        return false;
#endif
    });
    mainModule->accept(&instrument);

    instrument.setEntryAdvice(nullptr);
    instrument.setExitAdvice(epilogue);
    mainFunc->accept(&instrument);
#endif
}

void BinGen::addBssClear() {
    if(!addon) return;

#ifdef ARCH_AARCH64
    auto clearFunction = CIter::named(addon->getFunctionList())
        ->find("egalito_clear_addon_bss");
    if(!clearFunction) return;

#if !TARGET_IS_MAGENTA
    #define EARLIEST_FUNCTION_AFTER_SPSET   "_start"
#else
    #define EARLIEST_FUNCTION_AFTER_SPSET   "main"
#endif

    auto startFunction = CIter::named(mainModule->getFunctionList())
        ->find(EARLIEST_FUNCTION_AFTER_SPSET);
    if(!startFunction) return;

    SwitchContextPass switcher;
    clearFunction->accept(&switcher);

    InstrumentCallsPass instrument;
    instrument.setEntryAdvice(clearFunction);

    startFunction->accept(&instrument);
#endif
}

void BinGen::dePLT(void) {
    if(addon) {
        for(auto func : CIter::functions(addon)) {
            for(auto block : CIter::children(func)) {
                for(auto instr : CIter::children(block)) {
                    auto s = instr->getSemantic();
                    auto cfi = dynamic_cast<ControlFlowInstruction *>(s);
                    if(!cfi) continue;
                    auto link = dynamic_cast<PLTLink *>(cfi->getLink());
                    if(!link) continue;
                    auto target = link->getPLTTrampoline()->getTarget();
                    if(!target) {
                        LOG(1, "target is supposed to be resolved!");
                        LOG(1, "instr = " << std::hex << instr->getAddress());
                        throw "dePLT: error";
                    }
                    auto newLink = new NormalLink(target,
                        Link::SCOPE_EXTERNAL_CODE);
                    cfi->setLink(newLink);
                    delete link;
                }
            }
        }
    }
}


void BinGen::changeMapAddress(Module *module, address_t address) {
    auto bias = mainModule->getElfSpace()->getElfMap()->findSection(".text")
        ->getVirtualAddress();
    auto map = module->getElfSpace()->getElfMap();
    map->setBaseAddress(address - bias);
    LOG(1, "base address of " << module->getName() << " set to " << std::hex
        << map->getBaseAddress());
    for(auto region : CIter::regions(module)) {
        if(region == module->getDataRegionList()->getTLS()) continue;

        region->updateAddressFor(map->getBaseAddress());
    }
}

address_t BinGen::makeImageBox() {
    auto mainMap = setup->getConductor()->getMainSpace()->getElfMap();

    address_t startAddr = 0;
    for(void *s : mainMap->getSegmentList()) {
        Elf64_Phdr *phdr = static_cast<Elf64_Phdr *>(s);
        if(phdr->p_type != PT_LOAD) continue;

        startAddr = phdr->p_vaddr;
        break;
    }

    size_t length = mainMap->getLength();
    if(addon) {
        length += addon->getElfSpace()->getElfMap()->getLength();
    }

    return startAddr;
}

void BinGen::interleaveData() {
    address_t pos = endOfCode;
    LOG(1, "code ends at " << pos);

    pos = alignUp(pos, ".rodata");  // different protection
    pos = remapData(mainModule, pos, false);
    if(addon) {
        LOG(1, "rouding up pos " << pos << " to " << ROUND_UP_BY(pos, 8));
        pos = ROUND_UP_BY(pos, 8);
        pos = remapData(addon, pos, false);
    }
    endOfRoData = pos;

    pos = alignUp(pos, ".data");    // different protection
    pos = remapData(mainModule, pos, true);
    if(addon) {
        LOG(1, "rouding up pos " << pos << " to " << ROUND_UP_BY(pos, 8));
        pos = ROUND_UP_BY(pos, 8);
        pos = remapData(addon, pos, true);
    }
    endOfData = pos;

    pos = alignUp(pos, ".bss");     // different page
    LOG(1, "remapping in bss to box");
    pos = remapBss(mainModule, pos);
    if(addon) {
        pos = remapBss(addon, pos);
    }
    endOfBss = pos;
}

address_t BinGen::alignUp(address_t pos, const char *name) {
    size_t align = 0x1000;
    if(auto sec = mainModule->getElfSpace()->getElfMap()->findSection(name)) {
        // must be at least PAGE_SIZE for MMU
        align = std::max(align, sec->getAlignment());
    }

    LOG(1, "rouding up pos " << pos << " to " << ROUND_UP_BY(pos, align));
    return ROUND_UP_BY(pos, align);
}

address_t BinGen::remapData(Module *module, address_t pos, bool writable) {
    LOG(1, "remapping " << module->getName() << (writable ? " rw" : " ro")
        << "data");
    for(auto region : CIter::regions(module)) {
        if(region->writable() != writable) continue;

        std::vector<DataSection *> dataSectionList;
        for(auto section : CIter::children(region)) {
            if(section->isCode()) continue;
            if(section->isBss()) continue;

            dataSectionList.push_back(section);
        }
        std::sort(dataSectionList.begin(), dataSectionList.end(),
            [](DataSection *a, DataSection *b) {
                return a->getAddress() < b->getAddress();
            });

        for(auto sec : dataSectionList) {
            pos = ROUND_UP_BY(pos, sec->getAlignment());
            LOG(1, "   " << sec->getName() << " : " << pos);
            ChunkMutator(sec).setPosition(pos);
            pos += sec->getSize();
        }
    }

    return pos;
}

address_t BinGen::remapBss(Module *module, address_t pos) {
    LOG(1, "remapping " << module->getName() << " bss segments");
    for(auto region : CIter::regions(module)) {
        for(auto section : CIter::children(region)) {
            if(section->isBss()) {
                LOG0(1, "remap " << section->getAddress());
                ChunkMutator(section).setPosition(pos);
                LOG(1, " to " << section->getAddress());
                pos += section->getSize();
            }
        }
    }
    return pos;
}

void BinGen::resolveLinkerSymbol(Chunk *chunk, address_t address) {
    auto instruction = dynamic_cast<Instruction *>(chunk);
    if(instruction) {
        auto semantic = instruction->getSemantic();
        if(auto v = dynamic_cast<LinkedInstruction *>(semantic)) {
            auto oldLink = v->getLink();
            if(!dynamic_cast<UnresolvedLink *>(oldLink)) {
                LOG(1, "already linked?");
                return;
            }
            LOG(1, "overwriting the instruction target address " << std::hex
                << oldLink->getTargetAddress() << " to " << address);
            auto link = new UnresolvedLink(address);
            v->setLink(link);
            delete oldLink;
        }
    }
    else {
        auto var = dynamic_cast<DataVariable *>(chunk);
        auto oldLink = var->getDest();
        LOG(1, "overwriting the data target address " << std::hex
            << oldLink->getTargetAddress() << " to " << address);
        var->setDest(new UnresolvedLink(address));
        delete oldLink;
    }
}

void BinGen::fixMarkers() {
    LOG(1, "fixing marker address");
#if 0
    for(auto m : CIter::children(mainModule->getMarkerList())) {
        LOG(1, "marker " << m);
        if(auto symbol = m->getSymbol()) {
            if(0) { }
#if TARGET_IS_MAGENTA
            else if(!std::strcmp(symbol->getName(), "_end")) {
                // end of bss aligned up by 4096
                auto addr = ROUND_UP(endOfBss);
                m->setAddress(addr);
                LOG(1, symbol->getName() << " set to " << m->getAddress());
            }
            else if(!std::strcmp(symbol->getName(), "__code_start")) {
                // start of text: we did not change section address
                auto addr = startOfCode;
                m->setAddress(addr);
                LOG(1, symbol->getName() << " set to " << m->getAddress());
            }
            else if(!std::strcmp(symbol->getName(), "__code_end")) {
                // end of text
                auto addr = endOfCode;
                m->setAddress(addr);
                LOG(1, symbol->getName() << " set to " << m->getAddress());
            }
            else if(!std::strcmp(symbol->getName(), "__data_end")) {
                // end of all initialized data including init and fini
                auto addr = endOfData;
                m->setAddress(addr);
                LOG(1, symbol->getName() << " set to " << m->getAddress());
            }
            else if(!std::strcmp(symbol->getName(), "__bss_end")) {
                // end of bss segment aligned up by 16
                auto addr = ROUND_UP_BY(endOfBss, 16);
                m->setAddress(addr);
                LOG(1, symbol->getName() << " set to " << m->getAddress());
            }
#if 0
            else if(!std::strcmp(symbol->getName(), "__build_id_note_end")) {
                // next address of the end of .note.gnu.build-id
                auto addr = getSectionEndAddress(".note.gnu.build-id");
                m->setAddress(addr);
                LOG(1, symbol->getName() << " set to " << m->getAddress());
            }
            else if(!std::strcmp(symbol->getName(), "__init_array_end")) {
                // next address of the end of .init_array
                auto addr = getSectionEndAddress(".init_array");
                m->setAddress(addr);
                LOG(1, symbol->getName() << " set to " << m->getAddress());
            }
            else if(!std::strcmp(symbol->getName(), "__stop_lk_init")) {
                // next address of the end of lk_init
                auto addr = getSectionEndAddress("lk_init");
                m->setAddress(addr);
                LOG(1, symbol->getName() << " set to " << m->getAddress());
            }
#endif
#endif
            else {
                LOG(1, "unknown marker for " << symbol->getName());
            }
        }
        else {
            LOG(1, "marker with no name to " << m->getAddress());
        }
    }

    if(addon) {
        for(auto m : CIter::children(addon->getMarkerList())) {
            LOG(1, "[addon] marker " << m);
            if(auto symbol = m->getSymbol()) {
                LOG(1, "[addon] marker " << symbol->getName());
            }
            else {
                LOG(1, "[addon] marker with no name to " << m->getAddress());
            }
        }
    }
#endif
}

address_t BinGen::getSectionEndAddress(const char *sectionName) const {
    auto sec = mainModule->getElfSpace()->getElfMap()->findSection(sectionName);
    for(auto region : CIter::regions(mainModule)) {
        for(auto ds : CIter::children(region)) {
            auto original
                = region->getOriginalAddress() + ds->getOriginalOffset();
            if(original == sec->getVirtualAddress()) {
                return ds->getAddress() + ds->getSize();
            }
        }
    }

    LOG(1, "no section found! " << sectionName);
    return 0;
}

bool BinGen::fixLinkToSectionEnd(Chunk *chunk, ElfSection *section) {
    for(auto dr : CIter::regions(mainModule)) {
        for(auto dsec : CIter::children(dr)) {
            if(dr->getOriginalAddress() + dsec->getOriginalOffset()
                == section->getVirtualAddress()) {

                auto addr = dsec->getAddress() + dsec->getSize();
                LOG(1, "should point to " << addr);
                resolveLinkerSymbol(chunk, addr);
                return true;
            }
        }
    }
    return false;
}

void BinGen::writeOut(address_t pos) {
    LOG(1, "writing out main code " << pos);
    pos = writeOutCode(mainModule, pos);
    if(addon) {
        LOG(1, "writing out addon code " << pos);
        pos = writeOutCode(addon, pos);
    }

    LOG(1, "writing out main rodata " << pos);
    pos = writeOutRoData(mainModule, pos);
    if(addon) {
        LOG(1, "writing out addon rodata " << pos);
        pos = writeOutRoData(addon, pos);
    }

    LOG(1, "writing out main data " << pos);
    pos = writeOutRwData(mainModule, pos);
    if(addon) {
        LOG(1, "writing out addon data " << pos);
        pos = writeOutRwData(addon, pos);
    }
    LOG(1, "final pos = " << pos);
}

// this needs to write out PLT too (if addon is a library), unless dePLT()
// can handle that
address_t BinGen::writeOutCode(Module *module, address_t pos) {
    const int ll = 10;
    auto list = makeSortedFunctionList(module);

    for(auto func : list) {
        LOG(ll, "writing out " << func->getName()
            << ": pos " << pos << " vs function " << func->getAddress());
        LOG(ll, " size " << func->getSize());
        IF_LOG(ll) std::cout.flush();
        if(pos != func->getAddress()) {
            LOG(ll, "adding padding of size " << (func->getAddress() - pos));
            std::string zero(func->getAddress() - pos, 0);
            fs << zero;
        }

        for(auto block : CIter::children(func)) {
            for(auto instr : CIter::children(block)) {
#if 0
                ChunkDumper dumper;
                instr->accept(&dumper);
#endif

                std::string output;
                InstrWriterCppString writer(output);
                instr->getSemantic()->accept(&writer);
                fs << output;
            }
        }
        pos = func->getAddress() + func->getSize();
        LOG(ll, " to " << pos);
    }
    return pos;
}

address_t BinGen::writeOutRoData(Module *module, address_t pos) {
    return writeOutData(module, pos, false);
}

address_t BinGen::writeOutRwData(Module *module, address_t pos) {
    return writeOutData(module, pos, true);
}

address_t BinGen::writeOutData(Module *module, address_t pos, bool writable) {
    for(auto region : CIter::regions(module)) {
        if(region->writable() != writable) continue;

        LOG(1, "region at " << std::hex << region->getAddress());
        LOG(1, "  mem size " << region->getSize());

        for(auto dsec : CIter::children(region)) {
            if(dsec->isCode()) continue;
            if(dsec->isBss()) continue;

            auto vstart = dsec->getAddress();
            auto lstart
                = region->getAddress() + dsec->getOriginalOffset();
            if(pos != vstart) {
                LOG(1, "adding padding of size " << (vstart - pos));
                std::string zero(vstart - pos, 0);
                fs << zero;
                pos += vstart - pos;
            }
            auto size = dsec->getSize();
            LOG(1, "writing out data: "
                << " [ " << vstart << " , " << (vstart + size) << " ]");
            fs.write(reinterpret_cast<char *>(lstart), size);
            pos += size;
        }
    }
    return pos;
}
