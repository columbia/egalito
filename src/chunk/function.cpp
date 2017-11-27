#include <sstream>
#include <iomanip>
#include "function.h"
#include "serializer.h"
#include "visitor.h"
#include "elf/symbol.h"
#include "disasm/disassemble.h"
#include "instr/writer.h"
#include "instr/semantic.h"
#include "instr/serializer.h"
#include "operation/mutator.h"
#include "log/log.h"

#include "instr/concrete.h"
#include "dump.h"

Function::Function(address_t originalAddress)
    : symbol(nullptr), nonreturn(false) {

    std::ostringstream stream;
    stream << "fuzzyfunc-0x" << std::hex << originalAddress;
    name = stream.str();
}

Function::Function(Symbol *symbol) : symbol(symbol), nonreturn(false) {
    name = symbol->getName();
}

bool Function::hasName(std::string name) const {
    if(!symbol) return false;
    if(symbol->getName() == name) return true;
    for(auto s : symbol->getAliases()) {
        if(std::string(s->getName()) == name) {
            return true;
        }
    }

    return false;
}

void Function::serialize(ChunkSerializerOperations &op,
    ArchiveStreamWriter &writer) {

    LOG(10, "serialize function " << getName());

    writer.write(static_cast<uint64_t>(getAddress()));
    writer.writeAnyLength(getName());

#if 0  // don't use compression
    writer.write(static_cast<uint8_t>(0));
    op.serializeChildren(this, writer);
#else  // compress data
    writer.write(static_cast<uint8_t>(1));

    //op.serializeChildren(this, writer);  // serialize empty children!
    op.serializeChildrenIDsOnly(this, writer, 2);

    writer.write(static_cast<uint64_t>(
        this->getChildren()->getIterable()->getCount()));
    for(auto block : CIter::children(this)) {
        writer.write(static_cast<uint64_t>(
            block->getChildren()->getIterable()->getCount()));
        for(auto instr : CIter::children(block)) {
#if 1
            if(dynamic_cast<ControlFlowInstruction *>(instr->getSemantic())) {
                ChunkDumper dumper;
                instr->accept(&dumper);
            }
            InstrSerializer(op).serialize(instr->getSemantic(), writer);
#else
            InstrWriterGetData instrWriter;
            instr->getSemantic()->accept(&instrWriter);
            writer.writeAnyLength(instrWriter.get());
#endif
        }
    }
#endif
}

bool Function::deserialize(ChunkSerializerOperations &op,
    ArchiveStreamReader &reader) {

    uint64_t address;
    std::string name;
    reader.read(address);
    reader.readAnyLength(name);

    setPosition(new AbsolutePosition(address));
    setName(name);

    if(op.getVersion() == 2) {
        op.deserializeChildren(this, reader);
        return reader.stillGood();
    }

    uint8_t compressedMode = 0;
    reader.read(compressedMode);
    if(compressedMode == 0) {
        op.deserializeChildren(this, reader);
    }
    else {
        //op.deserializeChildren(this, reader);  // deserialize empty children!
        op.deserializeChildrenIDsOnly(this, reader, 2);

        PositionFactory *positionFactory = PositionFactory::getInstance();

        Chunk *prevChunk1 = this;
        //ChunkMutator mutator1(this);

        size_t totalSize = 0;
        uint64_t blockCount = 0;
        reader.read(blockCount);
        for(uint64_t b = 0; b < blockCount; b ++) {
            Block *block = getChildren()->getIterable()->get(b); //new Block();
            block->setPosition(positionFactory->makePosition(
                prevChunk1, block, this->getSize()));

            Chunk *prevChunk2 = block;
            //ChunkMutator mutator2(block, true);

            uint64_t instrCount = 0;
            reader.read(instrCount);
            for(uint64_t i = 0; i < instrCount; i ++) {
                auto instr = block->getChildren()->getIterable()->get(i); //new Instruction();
                auto semantic = InstrSerializer(op).deserialize(instr,
                    address + totalSize, reader);
                instr->setSemantic(semantic);
                totalSize += instr->getSize();

                instr->setPosition(positionFactory->makePosition(
                    prevChunk2, instr, block->getSize()));
                //mutator2.append(instr);
                prevChunk2 = instr;
            }

            //mutator1.append(block);
            prevChunk1 = block;
        }

        ChunkMutator(this, true);  // recalculate addresses
    }
    return reader.stillGood();
}

void Function::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}

void FunctionList::serialize(ChunkSerializerOperations &op,
    ArchiveStreamWriter &writer) {

    op.serializeChildren(this, writer);
}

bool FunctionList::deserialize(ChunkSerializerOperations &op,
    ArchiveStreamReader &reader) {

    op.deserializeChildren(this, reader);
    return reader.stillGood();
}

void FunctionList::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}
