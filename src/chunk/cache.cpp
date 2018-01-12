#include <cstring>
#include <cassert>
#include "cache.h"
#include "chunk/link.h"
#include "chunk/concrete.h"
#include "instr/semantic.h"
#include "instr/writer.h"
#include "log/log.h"
#include "log/temp.h"
#include "chunk/dump.h"

void ChunkCache::make(Chunk *chunk) {
    //TemporaryLogLevel tll("chunk", 10);
    //TemporaryLogLevel tll2("disasm", 10);

    LOG(10, "fixups for ChunkCache::make " << chunk->getName());
    this->address = chunk->getAddress();
    InstrWriterCppString writer(data);
    for(auto b : chunk->getChildren()->genericIterable()) {
        auto block = dynamic_cast<Block *>(b);
        for(auto i : CIter::children(block)) {
            auto semantic = i->getSemantic();
            semantic->accept(&writer);
            if(auto link = semantic->getLink()) {
                if(dynamic_cast<DataOffsetLink *>(link)) {
                    auto v = dynamic_cast<LinkedInstruction *>(semantic);
                    assert(v);

                    fixups.push_back(i->getAddress() + v->getDispOffset()
                        - chunk->getAddress());
                    IF_LOG(10) {
                        ChunkDumper d;
                        i->accept(&d);
                    }
                }
            }
        }
    }
}

void ChunkCache::copyAndFix(char *output) {
    std::memcpy(output, data.c_str(), data.size());
    for(auto offset : fixups) {
        uint32_t *point = reinterpret_cast<uint32_t *>(output + offset);
        int32_t delta = address - reinterpret_cast<address_t>(output);
        *point = *reinterpret_cast<const uint32_t *>(data.c_str() + offset)
            + delta;
    }
}
