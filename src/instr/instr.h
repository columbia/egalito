#ifndef EGALITO_INSTR_INSTR_H
#define EGALITO_INSTR_INSTR_H

#include "chunk/chunk.h"
#include "types.h"

class InstructionSemantic;
class SemanticVisitor;
class ChunkVisitor;

class Instruction : public AddressableChunkImpl {
private:
    InstructionSemantic *semantic;
public:
    Instruction(InstructionSemantic *semantic = nullptr)
        : semantic(semantic) {}

    virtual std::string getName() const;

    InstructionSemantic *getSemantic() const { return semantic; }
    void setSemantic(InstructionSemantic *semantic)
        { this->semantic = semantic; }

    virtual size_t getSize() const;
    virtual void setSize(size_t value);

    virtual void accept(ChunkVisitor *visitor);
};

#endif
