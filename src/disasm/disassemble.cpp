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
#include "log/temp.h"

#include "chunk/dump.h"

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

Module *Disassemble::module(ElfMap *elfMap, SymbolList *symbolList) {
    Module *module = new Module();
    FunctionList *functionList = new FunctionList();
    module->getChildren()->add(functionList);
    module->setFunctionList(functionList);
    functionList->setParent(module);

    //TemporaryLogLevel tll("disasm", 10);
    if(symbolList) {
        for(auto sym : *symbolList) {
            // skip Symbols that we don't think represent functions
            if(!sym->isFunction()) continue;

            Function *function = Disassemble::function(elfMap, sym, symbolList);
            functionList->getChildren()->add(function);
            function->setParent(functionList);
            LOG(10, "adding function " << function->getName()
                << " at " << std::hex << function->getAddress()
                << " size " << function->getSize());
        }
#if defined(ARCH_AARCH64) || defined(ARCH_ARM)
        for(auto sym : *symbolList) {
            if(!sym->isFunction()) {
                if(sym->getSize() == 0) continue;
                if(sym->getAliasFor()) continue;
                if(sym->getType() != Symbol::TYPE_NOTYPE) continue;
                auto sec = elfMap->findSection(sym->getSectionIndex());
                if(!sec) continue;  // ABS
                if(!(sec->getHeader()->sh_flags & SHF_EXECINSTR)) continue;
                if(sec->getName() == ".plt") continue;
                if(CIter::spatial(functionList)->findContaining(
                    sym->getAddress())) {

                    continue;
                }
                Function *function
                    = Disassemble::function(elfMap, sym, symbolList);
                functionList->getChildren()->add(function);
                function->setParent(functionList);
                LOG(1, "adding literal only function " << function->getName()
                    << " at " << std::hex << function->getAddress()
                    << " size " << function->getSize());
            }
        }
#endif
    }
    return module;
}

Function *Disassemble::function(ElfMap *elfMap, Symbol *symbol,
    SymbolList *symbolList) {

    auto sectionIndex = symbol->getSectionIndex();
    auto section = elfMap->findSection(sectionIndex);

    Handle handle(true);

    PositionFactory *positionFactory = PositionFactory::getInstance();
    Function *function = new Function(symbol);

    address_t symbolAddress = symbol->getAddress();
#ifdef ARCH_ARM
    symbolAddress &= ~1;
#endif

    function->setPosition(
        positionFactory->makeAbsolutePosition(symbolAddress));

    auto readAddress =
        section->getReadAddress() + section->convertVAToOffset(symbolAddress);
    auto readSize = symbol->getSize();
    auto virtualAddress = symbol->getAddress();

    if(auto mapping = getMappingSymbol(symbol)) {
        bool literal = processMappingSymbol(handle, mapping);
        if(literal) {
            processLiterals(
                handle, function, readAddress, readSize, virtualAddress);
        }
        else {
            disassembleBlocks(
                handle, function, readAddress, readSize, virtualAddress);
        }
        for(auto size = function->getSize();
            size < readSize;
            size = function->getSize()) {

            mapping = findMappingSymbol(symbolList, virtualAddress + size);
            if(!mapping) {
                // this is actually not literal if it is pointing to the
                // gap between the text and literal, but it's ok for now
                literal = true;
            }
            else {
                literal = processMappingSymbol(handle, mapping);
            }
            if(literal) {
                processLiterals(handle, function, readAddress + size,
                    readSize - size, virtualAddress + size);
            }
            else {
                disassembleBlocks(handle, function, readAddress + size,
                    readSize - size, virtualAddress + size);
            }
        }
    }
    else {
        disassembleBlocks(
            handle, function, readAddress, readSize, virtualAddress);
#ifdef ARCH_X86_64
        // no literals embedded -- it must be function size estimation error
#elif defined(ARCH_AARCH64)
        bool literal = true;
        for(auto size = function->getSize();
            size < readSize;
            size = function->getSize()) {

            if(literal) {
                processLiterals(handle, function, readAddress + size,
                    readSize - size, virtualAddress + size);
            }
            else {
                disassembleBlocks(handle, function, readAddress + size,
                    readSize - size, virtualAddress + size);
            }
            literal = !literal;
        }
#endif
    }

    {
        ChunkMutator m(function);  // recalculate cached values if necessary
    }

    return function;
}

void Disassemble::disassembleBlocks(Handle &handle, Function *function,
    address_t readAddress, size_t readSize, address_t virtualAddress) {

    PositionFactory *positionFactory = PositionFactory::getInstance();

    cs_insn *insn;
    LOG(19, "disassemble 0x" << std::hex << readAddress << " size " << readSize
        << ", virtual address " << virtualAddress);
    size_t count = cs_disasm(handle.raw(),
        (const uint8_t *)readAddress, readSize, virtualAddress, 0, &insn);

    Block *block = makeBlock(function, nullptr);

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

            block = makeBlock(function, block);
        }
    }

    if(block->getSize() > 0) {
        CLOG0(1, "fall-through function [%s]... "
            "adding basic block\n", function->getName().c_str());
        ChunkMutator(function, false).append(block);
    }
    if(block->getSize() == 0) {
        delete block;
    }

    cs_free(insn, count);
}

void Disassemble::processLiterals(Handle &handle, Function *function,
    address_t readAddress, size_t readSize, address_t virtualAddress) {

    LOG(10, "literals embedded in " << function->getName()
        << " at address 0x" << std::hex << virtualAddress);

    PositionFactory *positionFactory = PositionFactory::getInstance();

    Block *block = makeBlock(function, nullptr);

    Chunk *prevChunk = nullptr;
    if(function->getChildren()->getIterable()->getCount() > 0) {
        prevChunk = function->getChildren()->getIterable()->getLast();
    }

    for(size_t sz = 0; sz < readSize; sz += 4) {
        cs_insn *insn;
        size_t count = cs_disasm(handle.raw(),
                                 (const uint8_t *)readAddress + sz,
                                 readSize - sz,
                                 virtualAddress + sz,
                                 0,
                                 &insn);

        if(count > 0) {
            cs_free(insn, count);
            break;
        }

        auto instr = new Instruction();
        std::string raw;
        raw.assign(reinterpret_cast<char *>(readAddress + sz), 4);
        auto li = new LiteralInstruction(raw);
        instr->setSemantic(li);
        instr->setPosition(
            positionFactory->makePosition(prevChunk, instr, block->getSize()));
        prevChunk = instr;
        ChunkMutator(block, false).append(instr);
    }
    if(block->getSize() > 0) {
        ChunkMutator(function, false).append(block);
    }
    else {
        delete block;
    }
}

Block *Disassemble::makeBlock(Function *function, Block *prev) {
    PositionFactory *positionFactory = PositionFactory::getInstance();

    if(prev == nullptr) {
        if(function->getChildren()->getIterable()->getCount() > 0) {
            prev = function->getChildren()->getIterable()->getLast();
        }
    }
    Block *block = new Block();
    block->setPosition(
        positionFactory->makePosition(prev, block,
                                      function->getSize()));
    return block;
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
    // Note: we split on all explicit control flow changes like jumps, rets,
    // etc, but not on conditional moves or instructions that generate OS
    // interrupts/exceptions/traps.
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
#elif defined(ARCH_AARCH64)
    if(cs_insn_group(handle.raw(), ins, ARM64_GRP_JUMP)) {  // only branches
        split = true;
    }
    else if(ins->id == ARM64_INS_BL
        || ins->id == ARM64_INS_BLR
        || ins->id == ARM64_INS_RET) {

        split = true;
    }
#elif defined(ARCH_ARM)
    if(cs_insn_group(handle.raw(), ins, ARM_GRP_JUMP)) {
        split = true;
    }
    else if(ins->id == ARM_INS_B
        || ins->id == ARM_INS_BX
        || ins->id == ARM_INS_BL
        || ins->id == ARM_INS_BLX
        || ins->id == ARM_INS_BXJ
        || ins->id == ARM_INS_CBZ
        || ins->id == ARM_INS_CBNZ) {

        split = true;
    }
#endif
    return split;
}

Symbol *Disassemble::getMappingSymbol(Symbol *symbol) {
#if defined(ARCH_AARCH64) || defined(ARCH_ARM)
    for(auto sym : symbol->getAliases()) {
        if(sym->getName()[0] == '$') {
            return sym;
        }
    }
#endif
    return nullptr;
}

Symbol *Disassemble::findMappingSymbol(SymbolList *symbolList,
    address_t virtualAddress) {
#if defined(ARCH_AARCH64) || defined(ARCH_ARM)
    auto sym = symbolList->find(virtualAddress);
    if(sym) {
        if(sym->getName()[0] == '$') {
            return sym;
        }
        else {
            return getMappingSymbol(sym);
        }
    }
#endif
    return nullptr;
}

bool Disassemble::processMappingSymbol(Handle &handle, Symbol *symbol) {
#ifdef ARCH_X86_64
    return false;
#elif defined(ARCH_AARCH64) || defined(ARCH_ARM)
    bool literal = false;
    switch(symbol->getName()[1]) {
    case 'a':
        cs_option(handle.raw(), CS_OPT_MODE, CS_MODE_ARM);
        break;
    case 't':
        cs_option(handle.raw(), CS_OPT_MODE, CS_MODE_THUMB);
        break;
    case 'x':
        break;
    case 'd':
    default:
        literal = true;
        break;
    }
    return literal;
#endif
}
