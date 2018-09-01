#include <algorithm>
#include <fstream>
#include <cassert>
#include "jumptablepass.h"
#include "analysis/jumptable.h"
#include "analysis/jumptabledetection.h"
#include "config.h"
#include "chunk/jumptable.h"
#include "chunk/link.h"
#include "instr/concrete.h"  // for IndirectJumpInstruction
#include "operation/find.h"
#include "operation/find2.h"
#include "operation/mutator.h"
#include "elf/elfspace.h"

#undef DEBUG_GROUP
#define DEBUG_GROUP djumptable
#include "log/log.h"
#include "log/temp.h"

//#define CACHE_DIR "/tmp/egalito-cache"

void JumpTablePass::visit(Module *module) {
    this->module = module;
    auto jumpTableList = new JumpTableList();
    module->getChildren()->add(jumpTableList);
    module->setJumpTableList(jumpTableList);
    if(!loadFromFile(jumpTableList)) {
        visit(jumpTableList);
        saveToFile();
    }
}

void JumpTablePass::visit(JumpTableList *jumpTableList) {
    //TemporaryLogLevel tll("djumptable", 10, module->getName() == "module-(executable)");
    //TemporaryLogLevel tll2("analysis", 10, module->getName() == "module-(executable)");

    JumptableDetection search(module);
    search.detect(module);

    auto count1 = search.getTableList().size();
    while(1) {
        makeJumpTable(jumpTableList, search.getTableList());
        search.detect(module);
        auto count2 = search.getTableList().size();
        LOG(1, "count1 = " << count1 << " -> " << count2);
        if(count1 == count2) break;
        count1 = count2;
    }

#ifdef ARCH_X86_64
    // we cannot detect all the bounds in hand written assembly functions
    // yet, which means we need to rely on the other jump table passes.
    // Note, however, it is important to find at least ones that are
    // nested, like the ones in printf (though it is written in C)
    for(auto descriptor : search.getTableList()) {
        if(descriptor->getFunction()->hasName("__strncat_sse2_unaligned")
            || descriptor->getFunction()->hasName("__stpncpy_sse2_unaligned")
            || descriptor->getFunction()->hasName("__strncpy_sse2_unaligned")
            || descriptor->getFunction()->hasName("__strcat_sse2_unaligned")
            || descriptor->getFunction()->hasName("__stpcpy_sse2_unaligned")
            || descriptor->getFunction()->hasName("__strcpy_sse2_unaligned")
        ) {
            LOG(10, "resetting number of entries for assembly jump tables");
            descriptor->setEntries(0);
        }
    }
#endif
}

void JumpTablePass::makeJumpTable(JumpTableList *jumpTableList,
    const std::vector<JumpTableDescriptor *> &tables) {

    for(auto descriptor : tables) {
        // this constructor automatically creates JumpTableEntry children

        LOG(1, "constructing jump table at 0x"
            << std::hex << descriptor->getAddress() << " in ["
            << descriptor->getFunction()->getName() << "] with "
            << std::dec << descriptor->getEntries() << " entries, each of size "
            << std::dec << descriptor->getScale() << " for indirect jump at "
            << std::hex << descriptor->getInstruction()->getAddress());

        JumpTable *jumpTable = nullptr;
        int count = -1;
        auto it = tableMap.find(descriptor->getAddress());
        if(it != tableMap.end()) {
            // already exists
            jumpTable = (*it).second;
            if(jumpTable->getDescriptor() == descriptor) continue;
            auto otherCount = jumpTable->getEntryCount();
            auto thisCount = descriptor->getEntries();
            if(otherCount < 0 && thisCount >= 0) {
                count = descriptor->getEntries();
                //delete jumpTable->getDescriptor();
                jumpTable->setDescriptor(descriptor);
            }
            else if(otherCount >= 0 && thisCount >= 0) {
                if(otherCount != thisCount) {
                    LOG(1, "WARNING: overlapping jump tables at "
                        << std::hex << descriptor->getAddress() << " in ["
                        << descriptor->getFunction()->getName()
                        << "] with different sizes! " << std::dec
                        << otherCount << " vs " << thisCount);
                    count = std::max(otherCount, thisCount);
                    if(thisCount > otherCount) {
                        //delete jumpTable->getDescriptor();
                        jumpTable->setDescriptor(descriptor);
                    }
                }
            }
        }
        else {
            jumpTable = new JumpTable(
                module->getElfSpace()->getElfMap(), descriptor);
            count = jumpTable->getEntryCount();
            jumpTableList->getChildren()->add(jumpTable);
        }
        tableMap[jumpTable->getAddress()] = jumpTable;

        jumpTable->addJumpInstruction(descriptor->getInstruction());

        // create JumpTableEntry's
        auto n = makeChildren(jumpTable, count);
        if(n < (size_t)count) {
            jumpTable->getDescriptor()->setEntries(n);
        }
    }
}

size_t JumpTablePass::makeChildren(JumpTable *jumpTable, int count) {
    auto elfMap = module->getElfSpace()->getElfMap();
    auto descriptor = jumpTable->getDescriptor();

    auto section = descriptor->getContentSection();

    auto elfSection =
        module->getElfSpace()->getElfMap()->findSection(
            section->getName().c_str());
    auto tableReadPtr = module->getElfSpace()->getElfMap()
        ->getSectionReadPtr<unsigned char *>(elfSection);

    for(int i = 0; i < count; i ++) {
        auto address = jumpTable->getAddress() + i*descriptor->getScale();
        address_t offset = elfSection->convertVAToOffset(address);
        auto p = tableReadPtr + offset;
        ptrdiff_t value;
        switch(descriptor->getScale()) {
        case 1:
            value = *reinterpret_cast<int8_t *>(p);
            break;
        case 2:
            value = *reinterpret_cast<int16_t *>(p);
            break;
        case 4:
        default:
            value = *reinterpret_cast<int32_t *>(p);
            break;
        }
#ifdef ARCH_AARCH64
        // We only see the scale of 4 for hand-crafted jump tables in
        // printf_positional of glibc. If this assumption does not hold,
        // we should add another field to the descriptor.
        if(descriptor->getScale() != 4) {
            value *= 4;
        }
#endif
        auto targetBase = descriptor->getTargetBaseLink()->getTargetAddress();
        address_t target = targetBase + value;
        LOG(2, "    jump table entry " << i << " @ 0x" << std::hex << target);

        Chunk *inner = ChunkFind().findInnermostInsideInstruction(
            module->getFunctionList(), target);
        Link *link = nullptr;
        if(inner) {
            LOG(3, "        resolved to " << std::hex << inner->getName());
            link = new NormalLink(inner, Link::SCOPE_WITHIN_MODULE);
        }
        else {
            LOG(3, "        unresolved at 0x" << std::hex << target);
            //link = new UnresolvedLink(target);
            return i;
        }

        auto var = DataVariable::create(section, address, link, nullptr);
        var->setSize(descriptor->getScale());

        auto entry = new JumpTableEntry(var);
        entry->setPosition(PositionFactory::getInstance()
            ->makeAbsolutePosition(address));
        jumpTable->getChildren()->add(entry);
    }
    return count;
}

void JumpTablePass::saveToFile() const {
#ifdef CACHE_DIR
    if(module->getName() == "module-(executable)") return;
    if(module->getName() == "module-(egalito)") return;
    if(module->getName() == "module-(addon)") return;

    std::string filename(CACHE_DIR "/");
    filename += module->getName() + "-jumptable";
    std::ofstream f(filename.c_str(), std::ios::out);

    // keep it ascii now for debugging
    auto jumptablelist = module->getJumpTableList();
    for(auto& jt : CIter::children(jumptablelist)) {
        auto d = jt->getDescriptor();
        f << d->getInstruction()->getAddress() << '\n';
        f << d->getAddress() << '\n';
        f << d->getTargetBaseLink()->getTargetAddress() << '\n';
        f << d->getScale() << '\n';
        f << d->getEntries() << '\n';
    }

    f.close();
#endif
}

bool JumpTablePass::loadFromFile(JumpTableList *jumpTableList) {
#ifdef CACHE_DIR
    if(module->getName() == "module-(executable)") return false;
    if(module->getName() == "module-(egalito)") return false;
    if(module->getName() == "module-(addon)") return false;

    std::string filename(CACHE_DIR "/");
    filename += module->getName() + "-jumptable";
    std::ifstream f(filename.c_str(), std::ios::in);

    bool loaded = false;
    char line[128];
    // the only way to get Function * is by address; name can not be used,
    // because there may be multiple local functions with the same name.
    for(f.getline(line, 128); f.good(); f.getline(line, 128)) {
        auto brAddr = std::stoull(line);
        LOG(10, "instruction at 0x" << std::hex << brAddr);
        auto fn =
            CIter::spatial(module->getFunctionList())->findContaining(brAddr);
        auto instr = dynamic_cast<Instruction *>(
            ChunkFind().findInnermostAt(fn, brAddr));
        if(!instr) {
            LOG(1, "JumpTablePass: instruction not found");
        }

        f.getline(line, 128);
        auto addr = std::stoll(line);
        LOG(10, "address 0x" << std::hex << addr);
        f.getline(line, 128);
        auto targetBase = std::stoll(line);
        LOG(10, "target address 0x" << std::hex << targetBase);
        f.getline(line, 128);
        auto scale = std::stoi(line);
        LOG(10, "scale " << scale);
        f.getline(line, 128);
        auto entries = std::stoi(line);
        LOG(10, "entries " << entries);

        auto d = new JumpTableDescriptor(fn, instr);
        d->setAddress(addr);
        Link *link = nullptr;
        if(addr == targetBase) {
            link = LinkFactory::makeDataLink(module, targetBase, true);
        }
        else {
            auto function
                = dynamic_cast<Function *>(instr->getParent()->getParent());
            auto target = ChunkFind().findInnermostAt(function, targetBase);
            link = LinkFactory::makeNormalLink(target, true, false);
        }
        assert(link);
        d->setTargetBaseLink(link);

        d->setScale(scale);
        d->setEntries(entries);
        auto jumpTable = new JumpTable(module->getElfSpace()->getElfMap(), d);
        jumpTableList->getChildren()->add(jumpTable);
        auto n = makeChildren(jumpTable, entries);
        assert(n == (size_t)entries);
        loaded = true;
    }

    return loaded;
#else
    return false;
#endif
}
