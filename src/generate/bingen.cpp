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
#include "operation/mutator.h"
#include "pass/relocdata.h"
#include "pass/fixdataregions.h"

#include "log/log.h"
#include "chunk/dump.h"

#define ROUND_DOWN(x)       ((x) & ~0xfff)
#define ROUND_UP(x)         (((x) + 0xfff) & ~0xfff)
#define ROUND_UP_BY(x, y)   (((x) + (y) - 1) & ~((y) - 1))

BinGen::BinGen(ConductorSetup *setup, const char *filename)
    : setup(setup), addon(nullptr),
      fs(filename, std::ios::out | std::ios::binary) {

    for(auto module : CIter::children(setup->getConductor()->getProgram())) {
        if(module->getName() == "module-(addon)") {
            addon = module;
            break;
        }
    }
}

BinGen::~BinGen() {
    fs.close();
}

int BinGen::generate() {
    auto mainModule = setup->getConductor()->getProgram()->getMain();

    changeMapAddress(mainModule, 0xa0000000);

    address_t pos = makeImageBox();

    auto mainTextEnd = pos + getTextSize(mainModule);
    adjustAddOnCodeAddress(mainTextEnd);

    auto addOnTextEnd = mainTextEnd + getTextSize(addon);
    LOG(1, "mainTextEnd = " << mainTextEnd);
    LOG(1, "addOnTextEnd = " << addOnTextEnd
        << " textsize " << getTextSize(addon));
    SegMap::mapAllSegments(setup);

    //setup->getConductor()->fixDataSections();
    RelocDataPass relocData(setup->getConductor());
    setup->getConductor()->getProgram()->accept(&relocData);

    //changeMapAddress(mainModule, 0);
    mainModule->getElfSpace()->getElfMap()->setBaseAddress(0);
    interleaveData(addOnTextEnd);

    FixDataRegionsPass fixDataRegions;
    setup->getConductor()->getProgram()->accept(&fixDataRegions);

    writeOut(pos);

    return 0;
}

void BinGen::changeMapAddress(Module *module, address_t address) {
    auto map = module->getElfSpace()->getElfMap();
    map->setBaseAddress(address);
    for(auto region : CIter::regions(module)) {
        if(region == module->getDataRegionList()->getTLS()) continue;

        region->updateAddressFor(map->getBaseAddress());
    }
}

size_t BinGen::getTextSize(Module *module) {
    size_t size = 0;
    if(module) {
        for(auto region : CIter::children(module->getDataRegionList())) {
            if(!region->writable()) {
                size = region->getStartOffset();
                break;
            }
        }
    }
    return size;
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

    length = ROUND_UP(length);
    auto imageMap = mmap((void *)startAddr, length, PROT_READ | PROT_WRITE,
            MAP_ANONYMOUS | MAP_PRIVATE,
            -1, 0);
    if(imageMap == (void *)-1) {
        LOG(1, "failed to create image: no more memory");
        throw "mmap error";
    }
    if(imageMap != (void *)startAddr) {
        LOG(1, "failed to create image: overlapping");
        throw "mmap error";
    }

    LOG(1, "imageBox at " << startAddr << " length " << length);
    return startAddr;
}

void BinGen::interleaveData(address_t pos) {
    LOG(1, "rouding up pos " << pos << " to " << ROUND_UP_BY(pos, 8));
    pos = ROUND_UP_BY(pos, 8);
    LOG(1, "data should start at " << pos);
    auto mainModule = setup->getConductor()->getProgram()->getMain();
    LOG(1, "copying in main rodata");
    pos = copyInData(mainModule, pos, false);
    if(addon) {
        LOG(1, "rouding up pos " << pos << " to " << ROUND_UP_BY(pos, 8));
        pos = ROUND_UP_BY(pos, 8);
        LOG(1, "copying in addon rodata");
        pos = copyInData(addon, pos, false);
    }

    pos = ROUND_UP(pos);
    LOG(1, "copying in main rwdata to box");
    pos = copyInData(mainModule, pos, true);
    if(addon) {
        LOG(1, "rouding up pos " << pos << " to " << ROUND_UP_BY(pos, 8));
        pos = ROUND_UP_BY(pos, 8);
        LOG(1, "copying in addon rwdata to box");
        pos = copyInData(addon, pos, true);
    }
}

address_t BinGen::copyInData(Module *module, address_t pos, bool writable) {
    for(auto region : CIter::children(module->getDataRegionList())) {
        if(region->writable() != writable) continue;
        if(region->bss()) continue;

        LOG(1, "copying in to " << pos
            << " from " << (region->getAddress() + region->getStartOffset()));
        std::memcpy((void *)pos,
            (void *)(region->getAddress() + region->getStartOffset()),
            region->getSize() - region->getStartOffset());
        //ChunkMutator(region).setPosition(pos - region->getStartOffset());
        LOG(1, "offset is " << region->getStartOffset());
        ChunkMutator(region).setPosition(pos - region->getStartOffset());

        LOG(1, "base for " << region->getName() << " set to " << region->getAddress());
        pos += region->getSize() - region->getStartOffset();
    }

    return pos;
}

void BinGen::adjustAddOnCodeAddress(address_t pos) {
    if(addon) {
        for(auto func : CIter::functions(addon)) {
            pos = (pos + 0x7) & ~0x7;
            ChunkMutator(func).setPosition(pos);
            pos += func->getSize();
        }
    }
}

void BinGen::writeOut(address_t pos) {
    auto mainModule = setup->getConductor()->getProgram()->getMain();
    pos = writeOutCode(mainModule, pos);
    if(addon) {
        pos = writeOutCode(addon, pos);
    }

    LOG(1, "writing out main rodata");
    pos = writeOutRoData(mainModule, pos);
    if(addon) {
        LOG(1, "writing out addon rodata");
        pos = writeOutRoData(addon, pos);
    }

    LOG(1, "writing out main data");
    pos = writeOutRwData(mainModule, pos);
    if(addon) {
        LOG(1, "writing out addon data");
        pos = writeOutRwData(addon, pos);
    }
    LOG(1, "final pos = " << pos);
}

// this needs to write out PLTs too (if addon is a library)
address_t BinGen::writeOutCode(Module *module, address_t pos) {
    const int ll = 1;
    std::vector<Function *> list;
    for(auto func : CIter::functions(module)) {
        list.push_back(func);
    }
    std::sort(list.begin(), list.end(),
        [](Function *a, Function *b) {
            return a->getAddress() < b->getAddress();
        });

    for(auto func : list) {
        if(pos != func->getAddress()) {
            LOG(ll, "adding padding of size " << (func->getAddress() - pos));
            std::string zero(func->getAddress() - pos, 0);
            fs << zero;
        }
        LOG0(ll, "writing out function: " << func->getName()
            << " at " << func->getAddress());

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
    for(auto region : CIter::children(module->getDataRegionList())) {
        if(region->writable() != writable) continue;

        LOG(1, "region at " << region->getAddress());
        LOG(1, "  offset " << region->getStartOffset());
        LOG(1, "  size   " << region->getSize());
        LOG(1, "pos at " << pos);
        auto start = region->getAddress() + region->getStartOffset();
        if(pos != start) {
            LOG(1, "adding padding of size " << (start - pos));
            std::string zero(start - pos, 0);
            fs << zero;
            pos += start - pos;
        }
        auto size = region->getSize() - region->getStartOffset();
        LOG(1, "writing out data: " << region->getName()
            << " at " << start << " to " << (start + size));
        fs.write(reinterpret_cast<char *>(start), size);
        pos += size;
    }
    return pos;
}
