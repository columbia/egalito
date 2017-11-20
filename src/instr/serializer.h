#ifndef EGALITO_INSTR_SERIALIZER_H
#define EGALITO_INSTR_SERIALIZER_H

#include "semantic.h"
#include "archive/stream.h"

class Instruction;
class ChunkSerializerOperations;

class InstrSerializer {
private:
    ChunkSerializerOperations &op;
public:
    InstrSerializer(ChunkSerializerOperations &op) : op(op) {}

    void serialize(InstructionSemantic *semantic,
        ArchiveStreamWriter &writer);
    InstructionSemantic *deserialize(Instruction *instruction,
        address_t address, ArchiveStreamReader &reader);
private:
    InstructionSemantic *defaultDeserialize(Instruction *instruction,
        address_t address, ArchiveStreamReader &reader);
};

#endif
