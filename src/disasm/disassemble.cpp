#include <cstdio>
#include <cstring>
#include <capstone/x86.h>
#include <capstone/arm64.h>
#include <capstone/arm.h>
#include "disassemble.h"
#include "dump.h"
#include "makesemantic.h"
#include "elf/symbol.h"
#include "chunk/chunk.h"
#include "operation/mutator.h"
#include "instr/concrete.h"
#include "log/log.h"

Disassemble::Handle::Handle(bool detailed) {
#ifdef ARCH_X86_64
    if(cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        throw "Can't initialize capstone handle!";
    }
#elif defined(ARCH_AARCH64)
    if(cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &handle) != CS_ERR_OK) {
        throw "Can't initialize capstone handle!";
    }
#elif defined(ARCH_ARM)
    if(cs_open(CS_ARCH_ARM, CS_MODE_ARM, &handle) != CS_ERR_OK) {
        throw "Can't initialize capstone handle!";
    }
#endif

    cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);  // AT&T syntax
    if(detailed) {
        cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    }
}

Disassemble::Handle::~Handle() {
    cs_close(&handle);
}

void Disassemble::init() {
    if(PositionFactory::getInstance()) return;

    PositionFactory *positionFactory = new PositionFactory(
        //PositionFactory::MODE_DEBUGGING_NO_CACHE);  // 9.30 s
        //PositionFactory::MODE_CACHED_SUBSEQUENT);   // ~6.04 s
        PositionFactory::MODE_OFFSET);              // 5.89 s
        //PositionFactory::MODE_CACHED_OFFSET);       // 6.98 s
        //PositionFactory::MODE_GENERATION_SUBSEQUENT); // ~7.50 s
        //PositionFactory::MODE_GENERATION_OFFSET);
    PositionFactory::setInstance(positionFactory);
}

void Disassemble::debug(const uint8_t *code, size_t length,
    address_t realAddress, SymbolList *symbolList) {

    Handle handle(symbolList != 0);
    cs_insn *insn;
    size_t count = cs_disasm(handle.raw(), code, length, realAddress, 0, &insn);
    if(count == 0) {
        CLOG(3, "# empty");
        return;
    }
    for(size_t j = 0; j < count; j++) {
        const char *name = 0;
#ifdef ARCH_X86_64
        if(symbolList && insn[j].id == X86_INS_CALL) {
            cs_x86_op *op = &insn[j].detail->x86.operands[0];
            if(op->type == X86_OP_IMM) {
                unsigned long imm = op->imm;
                auto sym = symbolList->find(imm);
                if(sym) {
                    name = sym->getName();
                }
            }
        }
#elif defined(ARCH_AARCH64) || defined(ARCH_ARM)
        if(symbolList && insn[j].id == ARM64_INS_BL) {
            cs_arm64_op *op = &insn[j].detail->arm64.operands[0];
            if(op->type == ARM64_OP_IMM) {
                unsigned long imm = op->imm;
                auto sym = symbolList->find(imm);
                if(sym) {
                    name = sym->getName();
                }
            }
        }
#endif

        IF_LOG(3) {
            Assembly assembly(insn[j]);
            DisasmDump::printInstruction(
                insn[j].address, &assembly, INT_MIN, name);
        }
    }

    cs_free(insn, count);
}

#if defined(ARCH_ARM) || defined(ARCH_AARCH64)
Module *Disassemble::module(ElfMap *elfMap, SymbolList *symbolList, MappingSymbolList *mappingSymbolList) {
#else
Module *Disassemble::module(ElfMap *elfMap, SymbolList *symbolList) {
#endif
    Module *module = new Module();
    FunctionList *functionList = new FunctionList();
    module->getChildren()->add(functionList);
    module->setFunctionList(functionList);
    functionList->setParent(module);

    for(auto sym : *symbolList) {
        // skip Symbols that we don't think represent functions
        if(!sym->isFunction()) continue;

        if(true
#if 0
           || !strcmp(sym->getName(),"main")
           || !strcmp(sym->getName(),"parse_expression")
           || !strcmp(sym->getName(),"trecurse")
#endif
           ) {
#if defined(ARCH_ARM) || defined(ARCH_AARCH64)
          Function *function = Disassemble::function(elfMap, sym, mappingSymbolList);
#else
          Function *function = Disassemble::function(elfMap, sym);
#endif
            functionList->getChildren()->add(function);
            function->setParent(functionList);
            LOG(10, "adding function " << function->getName());
        }
    }
    return module;
}

void Disassemble::disassembleBlock(Handle &handle,
    Function *function, Block **blockRef, address_t readAddress,
    size_t readSize, address_t virtualAddress) {

    PositionFactory *positionFactory = PositionFactory::getInstance();

    cs_insn *insn;
    LOG(19, "disassemble 0x" << std::hex << readAddress << " size " << readSize
        << ", virtual address " << virtualAddress);
    size_t count = cs_disasm(handle.raw(), (const uint8_t *)readAddress, readSize, virtualAddress, 0, &insn);

    Block *block = *blockRef;

    for(size_t j = 0; j < count; j++) {
        auto ins = &insn[j];
  
        // check if this instruction ends the current basic block
        bool split = shouldSplitBlockAt(ins, handle);
  
        // Create Instruction from cs_insn
        auto instr = Disassemble::instruction(ins, handle, true);
        Chunk *prevChunk = nullptr;
        if(block->getChildren()->getIterable()->getCount() > 0) {
            prevChunk = block->getChildren()->getIterable()->getLast();
        }
        else if(function->getChildren()->getIterable()->getCount() > 0) {
            prevChunk = function->getChildren()->getIterable()->getLast();
        }
        else {
            prevChunk = nullptr;
        }
        instr->setPosition(
            positionFactory->makePosition(prevChunk, instr, block->getSize()));
  
        ChunkMutator(block, false).append(instr);
        if(split) {
            LOG(11, "split-instr in block: " << j+1);
            ChunkMutator(function, false).append(block);
  
            Block *oldBlock = block;
            block = new Block();
            *blockRef = block;
            block->setPosition(
                positionFactory->makePosition(oldBlock, block, function->getSize()));
        }
        else {
            LOG(11, "instr in block:" << j+1);
        }
    }

    cs_free(insn, count);
}


#if defined(ARCH_ARM) || defined(ARCH_AARCH64)
Function *Disassemble::function(ElfMap *elfMap, Symbol *symbol, MappingSymbolList *mappingSymbolList) {
#else
Function *Disassemble::function(ElfMap *elfMap, Symbol *symbol) {
#endif
    auto sectionIndex = symbol->getSectionIndex();
    auto section = elfMap->findSection(sectionIndex);
    Handle handle(true);

    PositionFactory *positionFactory = PositionFactory::getInstance();
    Function *function = new Function(symbol);

#if defined(ARCH_ARM)
    // Thumb symbols have LSBit set to 1. Actual data in LSBit set to 0.
    bool isThumbSymbol = (symbol->getAddress() & 1) == 1;
    address_t symbolAddress = isThumbSymbol ? (symbol->getAddress() & ~(1)) : symbol->getAddress();
#elif defined(ARCH_X86_64) || defined(ARCH_AARCH64)
    address_t symbolAddress = symbol->getAddress();
#endif

    function->setPosition(
        positionFactory->makeAbsolutePosition(symbolAddress));

    Block *block = new Block();
    block->setPosition(
        positionFactory->makePosition(nullptr, block, 0));

    auto readAddress = section->getReadAddress() + section->convertVAToOffset(symbolAddress);
    auto readSize = symbol->getSize();
    auto virtualAddress = symbol->getAddress();

#if defined(ARCH_ARM) || defined(ARCH_AARCH64)
    // If mapping symbols are present use them.
    if(mappingSymbolList) {
      std::vector<MappingSymbol *> *mappingSymbolsInRegion;

      if (mappingSymbolList) {
        mappingSymbolsInRegion = mappingSymbolList->findSymbolsInRegion(symbolAddress, symbolAddress + symbol->getSize());
      }

      for (auto mappingSymbol : *mappingSymbolsInRegion) {

        if(mappingSymbol->getType() == MappingSymbol::MAPPING_DATA) continue;

#if defined(ARCH_ARM)
        else if(mappingSymbol->getType() == MappingSymbol::MAPPING_THUMB) {
          cs_option(handle.raw(), CS_OPT_MODE, CS_MODE_THUMB);
        }
        else if(mappingSymbol->getType() == MappingSymbol::MAPPING_ARM) {
          cs_option(handle.raw(), CS_OPT_MODE, CS_MODE_ARM);
        }
#elif defined(ARCH_AARCH64)
        // Assumes AARCH64 code will only use 64bit code, hence $x and $d only.
        else if(mappingSymbol->getType() == MappingSymbol::MAPPING_AARCH64) {
          // Already in correct mode. Never switches.
        }
#endif
        readAddress = section->getReadAddress() + section->convertVAToOffset(mappingSymbol->getAddress());
        readSize = mappingSymbol->getSize() > symbol->getSize() ? symbol->getSize() : mappingSymbol->getSize();
        virtualAddress = mappingSymbol->getAddress();


        if (mappingSymbol->isLastMappingSymbol()) {
          size_t alreadyDisassembledSize = mappingSymbol->getAddress() - symbolAddress;
          readSize = symbol->getSize() - alreadyDisassembledSize;
        }

        disassembleBlock(handle, function, &block, readAddress, readSize, virtualAddress);
      }

      delete mappingSymbolsInRegion;
    }
    else {
      // TODO: Speculative Disassembly needed to determine if ARM, Thumb, AARCH64, data without Mapping Symbols.
      disassembleBlock(handle, function, &block, readAddress,
        readSize, virtualAddress);
    }
#else
    disassembleBlock(handle, function, &block, readAddress,
        readSize, virtualAddress);
#endif

    if(block->getSize() == 0) {
      delete block;
    }
    else {
        CLOG0(1, "fall-through function [%s]... "
            "adding basic block\n", symbol->getName());
        ChunkMutator(function, false).append(block);
    }

    {
        ChunkMutator m(function);  // recalculate cached values if necessary
    }

    return function;
}

Assembly Disassemble::makeAssembly(
    const std::vector<unsigned char> &str, address_t address) {

    Handle handle(true);

    cs_insn *insn;
    if(cs_disasm(handle.raw(), (const uint8_t *)str.data(), str.size(),
        address, 0, &insn) != 1) {

        throw "Invalid instruction opcode string provided\n";
    }
    Assembly assembly(*insn);
    cs_free(insn, 1);
    return assembly;
}

Instruction *Disassemble::instruction(
    const std::vector<unsigned char> &bytes, bool details, address_t address) {

    Handle handle(true);

    return instruction(handle, bytes, details, address);
}

Instruction *Disassemble::instruction(Handle &handle,
    const std::vector<unsigned char> &bytes, bool details, address_t address) {

  cs_insn *ins;
  if(cs_disasm(handle.raw(), (const uint8_t *)bytes.data(), bytes.size(),
               address, 0, &ins) != 1) {

    throw "Invalid instruction opcode string provided\n";
  }

  return instruction(ins, handle, details);
}

Instruction *Disassemble::instruction(cs_insn *ins, Handle &handle, bool details) {
    auto instr = new Instruction();
    InstructionSemantic *semantic = nullptr;

    semantic = MakeSemantic::makeNormalSemantic(instr, ins);

    if(!semantic) {
        if(details) {
            semantic = new DisassembledInstruction(Assembly(*ins));
        }
        else {
            std::string raw;
            raw.assign(reinterpret_cast<char *>(ins->bytes), ins->size);
            semantic = new RawInstruction(raw);
        }
    }
    instr->setSemantic(semantic);

    return instr;
}

bool Disassemble::shouldSplitBlockAt(cs_insn *ins, Handle &handle) {
    bool split = false;
#ifdef ARCH_X86_64
    if(cs_insn_group(handle.raw(), ins, X86_GRP_JUMP)) {
        split = true;
    }
    else if(cs_insn_group(handle.raw(), ins, X86_GRP_CALL)) {
        split = true;
    }
    else if(cs_insn_group(handle.raw(), ins, X86_GRP_RET)) {
        split = true;
    }
    /*else if(cs_insn_group(handle.raw(), ins, X86_GRP_INT)) {
    }
    else if(cs_insn_group(handle.raw(), ins, X86_GRP_IRET)) {
    }*/
#elif defined(ARCH_AARCH64)
    if(cs_insn_group(handle.raw(), ins, ARM64_GRP_JUMP)) { //only branches
        split = true;
    }
    else if(ins->id == ARM64_INS_BL) {
        split = true;
    }
    else if(ins->id == ARM64_INS_BLR) {
        split = true;
    }
    else if(ins->id == ARM64_INS_RET) {
        split = true;
    }
    //exception generation instructions don't require split
#elif defined(ARCH_ARM)
    if(cs_insn_group(handle.raw(), ins, ARM_GRP_JUMP)) {
      split = true;
    }
    else if(ins->id == ARM_INS_B) {
      split = true;
    }
    else if(ins->id == ARM_INS_BX) {
      split = true;
    }
    else if(ins->id == ARM_INS_BL) {
      split = true;
    }
    else if(ins->id == ARM_INS_BLX) {
      split = true;
    }
    else if(ins->id == ARM_INS_BXJ) {
      split = true;
    }
    else if(ins->id == ARM_INS_CBZ) {
      split = true;
    }
    else if(ins->id == ARM_INS_CBNZ) {
      split = true;
    }
#endif
      return split;
}
