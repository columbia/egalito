#include <algorithm>
#include "bingen.h"
#include "elf/elfspace.h"
#include "instr/semantic.h"
#include "instr/writer.h"

#include "log/log.h"
#include "chunk/dump.h"

void BinGen::generate() {
    std::vector<Function *> funcList;
    for(auto func : CIter::functions(elfSpace->getModule())) {
        funcList.push_back(func);
    }

    std::sort(funcList.begin(), funcList.end(),
        [](Function *a, Function *b) {
            return a->getAddress() < b->getAddress();
        });

    auto map = elfSpace->getElfMap();
    address_t end = map->findSection(1)->getVirtualAddress();
    for(auto f : funcList) {
        if(end != f->getAddress()) {
            LOG(1, "adding padding (0) of " << std::hex << (f->getAddress() - end));
            std::string zero(f->getAddress() - end, 0);
            fs << zero;
        }
        end = f->getAddress() + f->getSize();
        LOG(1, "writing out function: " << f->getName()
            << " at " << std::hex << f->getAddress()
            << " up to " << end);

        for(auto b : CIter::children(f)) {
            for(auto i : CIter::children(b)) {
                //ChunkDumper dumper;
                //i->accept(&dumper);

                std::string output;
                InstrWriterCppString writer(output);
                i->getSemantic()->accept(&writer);
                fs << output;
            }
        }
    }

    for(int i = 2; ; ++i) {
        auto sec = map->findSection(i);
        if(!sec) break;

        auto header = sec->getHeader();
        if(header->sh_type == SHT_NOBITS) continue;
        if(header->sh_flags & SHF_EXECINSTR) continue;
        if(!(header->sh_flags & SHF_ALLOC)) continue;
        if(header->sh_size == 0) continue;

        if(end != header->sh_addr) {
            LOG(1, "adding padding (0) of " << std::hex << (header->sh_addr - end));
            std::string zero(header->sh_addr - end, 0);
            fs << zero;
        }
        end = header->sh_addr + header->sh_size;
        LOG(1, "writing data at " << std::hex << header->sh_addr
            << " up to " << end);
        fs.write(reinterpret_cast<char *>(header->sh_addr), header->sh_size);
    }
}
