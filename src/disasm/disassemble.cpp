#include <cstdio>
#include <cstring>
#include <cassert>
#include <iterator>
#include <set>
#include <map>
#include <sstream>  // for debugging
#include <capstone/x86.h>
#include <capstone/arm64.h>
#include <capstone/arm.h>
#include "disassemble.h"
#include "dump.h"
#include "makesemantic.h"
#include "objectoriented.h"
#include "elf/symbol.h"
#include "chunk/chunk.h"
#include "chunk/size.h"
#include "operation/mutator.h"
#include "instr/concrete.h"
#include "util/intervaltree.h"
#include "instr/writer.h"  // for debugging
#include "log/log.h"
#include "log/temp.h"
#include "conductor/parseoverride.h"

#include "chunk/dump.h"

Module *Disassemble::module(ElfMap *elfMap, SymbolList *symbolList,
    DwarfUnwindInfo *dwarfInfo, SymbolList *dynamicSymbolList,
    RelocList *relocList) {

    if(symbolList) {
        LOG(1, "Creating module from symbol info");
        return makeModuleFromSymbols(elfMap, symbolList, dynamicSymbolList);
    }
    else if(dwarfInfo) {
        LOG(1, "Creating module from dwarf info");
        return makeModuleFromDwarfInfo(
            elfMap, dwarfInfo, dynamicSymbolList, relocList);
    }
    else {
        LOG(1, "Creating module without symbol info or dwarf info");
        return makeModuleFromDwarfInfo(
            elfMap, nullptr, dynamicSymbolList, relocList);
    }
}

Instruction *Disassemble::instruction(const std::vector<unsigned char> &bytes,
    bool details, address_t address) {

    DisasmHandle handle(true);
    return instruction(handle, bytes, details, address);
}
Instruction *Disassemble::instruction(DisasmHandle &handle,
    const std::vector<unsigned char> &bytes, bool details, address_t address) {

    return DisassembleInstruction(handle, details).instruction(bytes, address);
}
Instruction *Disassemble::instruction(cs_insn *ins, DisasmHandle &handle,
    bool details) {

    #ifdef ARCH_RISCV
    assert(0); // shouldn't be reached
    #endif

    return DisassembleInstruction(handle, details).instruction(ins);
}
#ifdef ARCH_RISCV
Instruction *Disassemble::instruction(rv_instr *ins, DisasmHandle &handle,
    bool details) {

    return DisassembleInstruction(handle, details).instruction(ins);
}
#endif

Assembly Disassemble::makeAssembly(const std::vector<unsigned char> &str,
    address_t address) {

    DisasmHandle handle(true);
    return DisassembleInstruction(handle, true).makeAssembly(str, address);
}

Module *Disassemble::makeModuleFromSymbols(ElfMap *elfMap,
    SymbolList *symbolList, SymbolList *dynamicSymbolList) {

    Module *module = new Module();
    FunctionList *functionList = new FunctionList();
    module->getChildren()->add(functionList);
    module->setFunctionList(functionList);
    functionList->setParent(module);

    if(!symbolList) return module;

#ifdef ARCH_X86_64
    /* consider any space between start of .text and first function as
        potential crt function locations */
    auto text = elfMap->findSection(".text");
    address_t smallest = -1u;
    bool foundCrtBegin = false;
    IntervalTree gaptree(Range(text->getVirtualAddress(), text->getSize()));

    for(auto it : (*symbolList)) {
        if(!it->isFunction()) continue;

        if(it->getAddress() >= text->getVirtualAddress()) {
            address_t gap = it->getAddress() - text->getVirtualAddress();
            if(gap < smallest) smallest = gap;
        }
    }

    DisasmHandle handle(true);
    DisassembleX86Function dx86(handle, elfMap);

    if(smallest != -1u && smallest > 0) {
	foundCrtBegin = true;
	gaptree.add(Range(text->getVirtualAddress(), smallest));
        dx86.disassembleCrtBeginFunctions(text,
	    Range(text->getVirtualAddress(), smallest), gaptree);
    }
#endif

    for(auto sym : *symbolList) {
        // skip Symbols that we don't think represent functions
        if(!sym->isFunction()) continue;

        Function *function = Disassemble::function(elfMap, sym, symbolList,
            dynamicSymbolList);
        functionList->getChildren()->add(function);
        function->setParent(functionList);
        LOG(10, "adding function " << function->getName()
            << " at " << std::hex << function->getAddress()
            << " size " << function->getSize());
    }

#ifdef ARCH_X86_64
    // If we still haven't found the crtbegin functions,
    // try searchin the region between the entry point (eg. _start)
    // and the next function
    if (!foundCrtBegin) {
	std::map<address_t, Function *> funcsFound;

	for (auto func : CIter::children(functionList)) {
	    funcsFound[func->getAddress()] = func;
	}

	auto startAddr = elfMap->getEntryPoint();
	auto beforeIt = funcsFound.lower_bound(startAddr);
	auto afterIt = funcsFound.upper_bound(startAddr);
	if ((beforeIt != funcsFound.end()) &&
	    (afterIt != funcsFound.end())) {
	    Function *startFunc = beforeIt->second;
	    Function *afterFunc = afterIt->second;
	    assert(startFunc);
	    assert(afterFunc);

	    LOG(1, "DM:  Start:  " << startFunc->getAddress()
		<< ", After:  " << afterFunc->getAddress());

	    Range startGap =
		Range::fromEndpoints(startFunc->getAddress(),
				     afterFunc->getAddress());
	    gaptree.add(startGap);
	    dx86.disassembleCrtBeginFunctions(text, startGap, gaptree);
	    foundCrtBegin = true;
	}
    }

    if (foundCrtBegin) {
	for(auto &r : gaptree.getAllData()) {
	    Function *function = dx86.fuzzyFunction(r, text);
	    functionList->getChildren()->add(function);
	    function->setParent(functionList);
	    LOG(10, "adding function " << function->getName()
		<< " at " << std::hex << function->getAddress()
		<< " size " << function->getSize());
	}
    }
#endif

#if defined(ARCH_AARCH64) || defined(ARCH_ARM)
    for(auto sym : *symbolList) {
        if(!sym->isFunction()) {
            // this misses some cases where there are only mapping symbols
            // for literals (__multc3 in libm compiled with old gcc)
            if(sym->getSize() == 0) continue;
            if(sym->getAliasFor()) continue;
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
            LOG(10, "adding literal only function " << function->getName()
                << " at " << std::hex << function->getAddress()
                << " size " << function->getSize());
        }
    }
#endif

    return module;
}

Module *Disassemble::makeModuleFromDwarfInfo(ElfMap *elfMap,
    DwarfUnwindInfo *dwarfInfo, SymbolList *dynamicSymbolList,
    RelocList *relocList) {

    Module *module = new Module();

    FunctionList *functionList = linearDisassembly(elfMap, ".text",
        dwarfInfo, dynamicSymbolList, relocList);
    module->getChildren()->add(functionList);
    module->setFunctionList(functionList);
    functionList->setParent(module);

    return module;
}

FunctionList *Disassemble::linearDisassembly(ElfMap *elfMap,
    const char *sectionName, DwarfUnwindInfo *dwarfInfo,
    SymbolList *dynamicSymbolList, RelocList *relocList) {

    DisasmHandle handle(true);
    DisassembleFunction disassembler(handle, elfMap);
    return disassembler.linearDisassembly(
        sectionName, dwarfInfo, dynamicSymbolList, relocList);
}

Function *Disassemble::function(ElfMap *elfMap, Symbol *symbol,
    SymbolList *symbolList, SymbolList *dynamicSymbolList) {

    DisasmHandle handle(true);
    DisassembleFunction disassembler(handle, elfMap);
#ifdef ARCH_X86_64
    return disassembler.function(symbol, symbolList, dynamicSymbolList);
#else
    return disassembler.function(symbol, symbolList);
#endif
}

bool DisassembleAARCH64Function::processMappingSymbol(Symbol *symbol) {
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
}

Instruction *DisassembleInstruction::instruction(const std::string &bytes,
    address_t address) {

    auto ins = runDisassembly(
        reinterpret_cast<const uint8_t *>(bytes.c_str()),
        bytes.length(), address);
    auto ret = instruction(ins);

    free(ins);

    return ret;
}

Instruction *DisassembleInstruction::instruction(
    const std::vector<unsigned char> &bytes, address_t address) {

    auto ins = runDisassembly(static_cast<const uint8_t *>(bytes.data()),
        bytes.size(), address);

    auto ret = instruction(ins);

    free(ins);

    return ret;
}

Instruction *DisassembleInstruction::instruction(cs_insn *ins) {
    auto instr = new Instruction();
    InstructionSemantic *semantic = nullptr;

    #ifdef ARCH_RISCV
    assert(0); // should never be reached
    #endif

    semantic = MakeSemantic::makeNormalSemantic(instr, ins);

    if(!semantic) {
        //LOG(1, "Warning: unknown instruction, defaulting to Isolated");
        if(details) {
            semantic = new IsolatedInstruction();
            semantic->setAssembly(AssemblyPtr(new Assembly(*ins)));
        }
        else {
            std::string raw;
            raw.assign(reinterpret_cast<char *>(ins->bytes), ins->size);
            auto isolated = new IsolatedInstruction();
            isolated->setData(raw);
            semantic = isolated;
        }
    }
    instr->setSemantic(semantic);

    return instr;
}

#ifdef ARCH_RISCV
Instruction *DisassembleInstruction::instruction(rv_instr *ins) {
    auto instr = new Instruction();
    InstructionSemantic *semantic = nullptr;

    semantic = MakeSemantic::makeNormalSemantic(instr, ins);
    if(!semantic) {
        auto isolated = new IsolatedInstruction();
        std::string raw;
        raw.assign(reinterpret_cast<char *>(&ins->inst), ins->len);
        isolated->setData(raw);
        semantic = isolated;
    }
    assert(semantic); // XXX: this should be more flexible, as above
    instr->setSemantic(semantic);

    return instr;
}
#endif

InstructionSemantic *DisassembleInstruction::instructionSemantic(
    Instruction *instr, const std::string &bytes, address_t address) {

    auto ins = runDisassembly(
        reinterpret_cast<const uint8_t *>(bytes.c_str()),
        bytes.length(), address);

    InstructionSemantic *semantic = nullptr;
    semantic = MakeSemantic::makeNormalSemantic(instr, ins);

    if(!semantic) {
        //LOG(1, "Warning: unknown instruction, defaulting to Isolated");
        if(details) {
            semantic = new IsolatedInstruction();
            semantic->setAssembly(AssemblyPtr(new Assembly(*ins)));
            for(auto c : semantic->getData()) LOG(1, "    " << (int)c);
        }
        else {
            std::string raw;
            #ifndef ARCH_RISCV
            raw.assign(reinterpret_cast<char *>(ins->bytes), ins->size);
            #else
            raw.assign(reinterpret_cast<char *>(&ins->inst), ins->len);
            #endif
            auto isolated = new IsolatedInstruction();
            isolated->setData(raw);
            semantic = isolated;
            for(auto c : semantic->getData()) LOG(1, "    " << (int)c);
        }
    }
    instr->setSemantic(semantic);
    return semantic;
}

InstructionSemantic *DisassembleInstruction::instructionSemantic(
    Instruction *instr, const std::vector<unsigned char> &bytes,
    address_t address) {

    return instructionSemantic(instr,
        std::string(reinterpret_cast<const char *>(bytes.data()), bytes.size()),
        address);
}

Assembly *DisassembleInstruction::allocateAssembly(const std::string &bytes,
    address_t address) {

    auto insn = runDisassembly(
        reinterpret_cast<const uint8_t *>(bytes.c_str()),
        bytes.length(), address);
    Assembly *assembly = new Assembly(*insn);
    #ifndef ARCH_RISCV
    cs_free(insn, 1);
    #else
    delete insn;
    #endif

    return assembly;
}

Assembly *DisassembleInstruction::allocateAssembly(
    const std::vector<unsigned char> &bytes, address_t address) {

    auto insn = runDisassembly(static_cast<const uint8_t *>(bytes.data()),
        bytes.size(), address);
    Assembly *assembly = new Assembly(*insn);
    #ifndef ARCH_RISCV
    cs_free(insn, 1);
    #else
    delete insn;
    #endif

    return assembly;
}

AssemblyPtr DisassembleInstruction::makeAssemblyPtr(const std::string &bytes,
    address_t address) {

    return AssemblyPtr(allocateAssembly(bytes, address));
}

AssemblyPtr DisassembleInstruction::makeAssemblyPtr(
    const std::vector<unsigned char> &bytes, address_t address) {

    return AssemblyPtr(allocateAssembly(bytes, address));
}

Assembly DisassembleInstruction::makeAssembly(
    const std::vector<unsigned char> &bytes, address_t address) {

    auto insn = runDisassembly(
        reinterpret_cast<const uint8_t *>(bytes.data()),
        bytes.size(), address);
    Assembly assembly(*insn);

    #ifndef ARCH_RISCV
    cs_free(insn, 1);
    #else
    delete insn;
    #endif

    return assembly;
}

#ifndef ARCH_RISCV
cs_insn *DisassembleInstruction::runDisassembly(const uint8_t *bytes,
    size_t size, address_t address) {

    cs_insn *ins;
    if(cs_disasm(handle.raw(), bytes, size, address, 0, &ins) != 1) {
        IF_LOG(1) {
            std::ostringstream stream;
            stream << "address: " << std::hex << address << ", bytes:";
            for(size_t i = 0; i < size; i ++) {
                stream << std::hex << " " << (int)bytes[i];
            }
            LOG(1, stream.str());
        }

        throw "Invalid instruction opcode string provided\n";
    }

    return ins;
}
#else
rv_instr *DisassembleInstruction::runDisassembly(const uint8_t *bytes,
    size_t size, address_t address) {

    assert(size == 2 || size == 4);

    rv_instr *ins = new rv_instr;
    auto buf = rv_disasm_buffer(rv64, address, bytes, size);
    if(buf.size() == 0) {
        LOG(1, "When disassembling at address " << address);
        LOG(1, "bytes: (len " << std::dec << size << ")");
        for(size_t i = 0; i < size; i ++) {
            CLOG(1, "    %x\n", bytes[i]);
        }
        throw "Invalid instruction provided\n";
    }
    assert(buf.size() == 1);
    *ins = buf[0];

    return ins;
}
#endif

// --- X86_64 disassembly code

Function *DisassembleX86Function::function(Symbol *symbol,
    SymbolList *symbolList, SymbolList *dynamicSymbolList) {

    auto sectionIndex = symbol->getSectionIndex();
    auto section = elfMap->findSection(sectionIndex);

    PositionFactory *positionFactory = PositionFactory::getInstance();
    Function *function = new Function(symbol);

    address_t symbolAddress = symbol->getAddress();
    function->setPosition(
        positionFactory->makeAbsolutePosition(symbolAddress));

    if(dynamicSymbolList) {
        if(auto dsym = dynamicSymbolList->find(symbolAddress)) {
            function->setDynamicSymbol(dsym); 
        }
    }

    auto readAddress =
        section->getReadAddress() + section->convertVAToOffset(symbolAddress);
    auto readSize = symbol->getSize();
    auto virtualAddress = symbol->getAddress();

    auto context = ParseOverride::getInstance()->makeContext(
        function->getSymbol()->getName());

    if(auto over = ParseOverride::getInstance()->getBlockBoundaryOverride(
        context)) {

        LOG(10, "Using parsing override!");

        disassembleCustomBlocks(function, readAddress, virtualAddress,
            over->getOverrideList());

    }
    else {
        disassembleBlocks(
            function, readAddress, readSize, virtualAddress);
    }

    {
        ChunkMutator m(function);  // recalculate cached values if necessary
    }

    return function;
}

Function *DisassembleX86Function::fuzzyFunction(const Range &range,
    ElfSection *section) {

    address_t virtualAddress = section->getVirtualAddress();
    address_t readAddress = section->getReadAddress()
        + section->convertVAToOffset(virtualAddress);
    address_t intervalVirtualAddress = range.getStart();
    address_t intervalOffset = intervalVirtualAddress - virtualAddress;
    address_t intervalSize = range.getSize();

    Function *function = new Function(intervalVirtualAddress);

    PositionFactory *positionFactory = PositionFactory::getInstance();
    function->setPosition(
        positionFactory->makeAbsolutePosition(intervalVirtualAddress));

    disassembleBlocks(function, readAddress + intervalOffset,
        intervalSize, intervalVirtualAddress);

    {
        ChunkMutator m(function);  // recalculate cached values if necessary
    }

    return function;
}

void DisassembleX86Function::firstDisassemblyPass(ElfSection *section,
    IntervalTree &splitRanges, IntervalTree &functionPadding) {

    // Get address of region to disassemble
    address_t virtualAddress = section->getVirtualAddress();
    address_t readAddress = section->getReadAddress()
        + section->convertVAToOffset(virtualAddress);
    size_t readSize = section->getSize();

    cs_insn *insn;
    size_t count = cs_disasm(handle.raw(),
        (const uint8_t *)readAddress, readSize, virtualAddress, 0, &insn);

    size_t nopBytes = 0;
    //enum { PROLOGUE_NONE, PROLOGUE_PUSH } prologueState = PROLOGUE_NONE;
    for(size_t j = 0; j < count; j++) {
        auto ins = &insn[j];

        address_t target = 0;
        if(shouldSplitFunctionDueTo(ins, &target)) {
            splitRanges.splitAt(target);
        }

        if(ins->id == X86_INS_NOP) {
            nopBytes += ins->size;
        }
        else if(nopBytes) {
            functionPadding.add(Range(ins->address - nopBytes, nopBytes));
            nopBytes = 0;
        }

#if 0
        switch(prologueState) {
        case PROLOGUE_NONE:
            if(ins->id == X86_INS_PUSH && ins->detail->x86.op_count == 1
                && ins->detail->x86.operands[0].type == X86_OP_REG
                && ins->detail->x86.operands[0].reg == X86_REG_RBP) {

                prologueState = PROLOGUE_PUSH;
            }
            break;
        case PROLOGUE_PUSH:
            if(ins->id == X86_INS_MOV && ins->detail->x86.op_count == 2
                && ins->detail->x86.operands[0].type == X86_OP_REG
                && ins->detail->x86.operands[1].type == X86_OP_REG
                && ins->detail->x86.operands[0].reg == X86_REG_RSP
                && ins->detail->x86.operands[1].reg == X86_REG_RBP) {

                splitRanges.splitAt(ins->address - 1);  // back before push
            }
            prologueState = PROLOGUE_NONE;
            break;
        }
#endif
    }

    if(nopBytes) {
        functionPadding.add(Range(virtualAddress + readSize - nopBytes,
            nopBytes));
    }

    if(count > 0) cs_free(insn, count);
}

// for deregister_tm_clones, register_tm_clones, __do_global_dtors_aux, and frame_dummy
void DisassembleX86Function::disassembleCrtBeginFunctions(ElfSection *section,
    Range crtbegin, IntervalTree &splitRanges) {

    LOG(1, "range: " << std::hex << crtbegin.getStart() << " " << crtbegin.getSize());

    cs_insn *insn;
    size_t count = cs_disasm(handle.raw(),
        (const uint8_t *)section->getReadAddress()
            + section->convertVAToOffset(crtbegin.getStart()),
        crtbegin.getSize(), crtbegin.getStart(), 0, &insn);

    // We find the crtbegin functions by extrapolating from the ret statements
    // that are followed by nops. Because these functions are very strange, the
    // padding nops are not stripped from the functions (to match symbol info).
    enum {
        MODE_NONE,          // starting
        MODE_RET,           // seen a ret
        MODE_NOP,           // seen a ret and one or more nops
        MODE_MAYBE_FOUND,   // almost done, but filter out ret+nop+ret
        MODE_FOUND          // done, end the function!
    } mode = MODE_NONE;

    for(size_t j = 0; j < count; j++) {
        auto ins = &insn[j];

        bool redo;
        do {
            redo = false;
            switch(mode) {
            case MODE_NONE:
                if(ins->id == X86_INS_RET) mode = MODE_RET;
                break;
            case MODE_RET:
                if(ins->id == X86_INS_NOP) mode = MODE_NOP;
                else mode = MODE_NONE, redo = true;
                break;
            case MODE_NOP:
                if(ins->id == X86_INS_NOP) mode = MODE_NOP;
                else mode = MODE_MAYBE_FOUND, redo = true;
                break;
            case MODE_MAYBE_FOUND:
                // if we see ret+nop+ret sequence, wait until second ret
                if(ins->id == X86_INS_RET) mode = MODE_RET;
                else mode = MODE_FOUND, redo = true;
                break;
            case MODE_FOUND:
                LOG(1, "splitting crtbegin function at 0x"
                    << std::hex << ins->address);
                splitRanges.splitAt(ins->address);
                mode = MODE_NONE, redo = true;
                break;
            }
        } while(redo);
    }

    if(count > 0) cs_free(insn, count);
}

FunctionList *DisassembleX86Function::linearDisassembly(const char *sectionName,
    DwarfUnwindInfo *dwarfInfo, SymbolList *dynamicSymbolList,
    RelocList *relocList) {

    auto section = elfMap->findSection(sectionName);
    if(!section) return nullptr;

    Range sectionRange(section->getVirtualAddress(), section->getSize());

    // Find known functions from DWARF info
    IntervalTree knownFunctions(sectionRange);
    for(auto it = dwarfInfo->fdeBegin(); it != dwarfInfo->fdeEnd(); it ++) {
        DwarfFDE *fde = *it;
        Range range(fde->getPcBegin(), fde->getPcRange());
        if(knownFunctions.add(range)) {
            LOG(12, "DWARF FDE at [" << std::hex << fde->getPcBegin() << ",+"
                << fde->getPcRange() << "]");
        }
        else {
            LOG(1, "FDE is out of bounds of .text section, skipping");
        }
    }

    // Known functions from symbol information as well
    for(size_t i = 0; i < dynamicSymbolList->getCount(); i ++) {
        Symbol *symbol = dynamicSymbolList->get(i);
        // only care about functions/ifuncs
        if(symbol->getType() != Symbol::TYPE_FUNC
            && symbol->getType() != Symbol::TYPE_IFUNC) {

            continue;
        }
        if(symbol->getSize() == 0) {
            LOG(1, "dynamic function [" << symbol->getName()
                << "] has size 0, skipping.");
            continue;
        }
        Range range(symbol->getAddress(), symbol->getSize());
        if(knownFunctions.add(range)) {
            LOG(12, "Dynamic symbol at [" << std::hex << symbol->getAddress()
                << ",+" << symbol->getSize() << "]");
        }
        else {
            LOG(1, "Dynamic symbol is out of bounds of .text section, skipping");
        }
    }

    // Run first disassembly pass, to find obvious function boundaries
    IntervalTree splitRanges(sectionRange);
    splitRanges.add(sectionRange);
    splitRanges.splitAt(elfMap->getEntryPoint());
    if(auto s = elfMap->findSection(".init_array")) {
        for(size_t i = 0; i < s->getSize(); i ++) {
            splitRanges.splitAt(*reinterpret_cast<address_t *>(s->getReadAddress() + i));
        }
    }
    if(auto s = elfMap->findSection(".fini_array")) {
        for(size_t i = 0; i < s->getSize(); i ++) {
            splitRanges.splitAt(*reinterpret_cast<address_t *>(s->getReadAddress() + i));
        }
    }

    IntervalTree functionPadding(sectionRange);
    firstDisassemblyPass(section, splitRanges, functionPadding);

    // Shrink functions, removing nop padding bytes
    IntervalTree functionsWithoutPadding(sectionRange);
    splitRanges.getRoot()->inStartOrderTraversal([&] (Range func) {
        Range bound;
        if(functionPadding.findLowerBoundOrOverlapping(func.getEnd(), &bound)) {
            LOG(10, "looks like function " << func << " may have some padding");
            if(func.getEnd() == bound.getEnd() || bound.contains(func.getEnd())) {
                functionsWithoutPadding.add(Range::fromEndpoints(
                    func.getStart(), bound.getStart()));
            }
            else {
                functionsWithoutPadding.add(func);
            }
        }
    });

    // Remove nop padding byte ranges after all known functions
    // (achieved by removing all functions plus nops, then adding back in)
    knownFunctions.getRoot()->inStartOrderTraversal([&] (Range func) {
        Range bound;
        if(functionPadding.findLowerBoundOrOverlapping(func.getEnd(), &bound)) {
            LOG(10, "looks like function " << func << " may have some padding");
            if(func.getEnd() == bound.getEnd() || bound.contains(func.getEnd())) {
                // Subtracts func, and if any single range would be subtracted,
                // we also subtract the nop padding from that range. This
                // avoids enroaching into functions that begin with a nop.
                functionsWithoutPadding.subtractWithAddendum(func, bound);
            }
            else {
                functionsWithoutPadding.subtract(func);
            }
        }
        else {
            // No nop padding bytes, just subtract function
            functionsWithoutPadding.subtract(func);
        }
    });
    functionsWithoutPadding.unionWith(knownFunctions);  // add back in

    // Hack to find the crtbegin functions...
    auto entryPoint = elfMap->getEntryPoint();
    Range crtBeginFunction;  // blob of all crtbegin functions
    if(functionsWithoutPadding.findUpperBound(
        entryPoint, &crtBeginFunction)) {

        disassembleCrtBeginFunctions(section, crtBeginFunction,
            functionsWithoutPadding);
    }

    // Get final list of functions (add special functions outside .text)
    std::vector<Range> intervalList = functionsWithoutPadding.getAllData();
    if(auto s = elfMap->findSection(".init")) {
        intervalList.push_back(Range(s->getVirtualAddress(), s->getSize()));
    }
    if(auto s = elfMap->findSection(".fini")) {
        intervalList.push_back(Range(s->getVirtualAddress(), s->getSize()));
    }

    LOG(1, "Splitting code section into " << intervalList.size()
        << " fuzzy functions");

    FunctionList *functionList = new FunctionList();
    for(const Range &range : intervalList) {
        LOG(11, "Split into function " << range << " at section offset "
            << section->convertVAToOffset(range.getStart()));
        Function *function = fuzzyFunction(range, section);

        if(auto dsym = dynamicSymbolList->find(range.getStart())) {
            LOG(12, "    renaming fuzzy function [" << function->getName()
                << "] to [" << dsym->getName() << "]");
            function->setName(dsym->getName());
            function->setDynamicSymbol(dsym);
        }

        functionList->getChildren()->add(function);
        function->setParent(functionList);
    }

    return functionList;
}

// --- AARCH64 disassembly code

// We do not handle binaries that contain embedded literals in code without
// mapping symbols.

Function *DisassembleAARCH64Function::function(Symbol *symbol,
    SymbolList *symbolList) {

    auto sectionIndex = symbol->getSectionIndex();
    auto section = elfMap->findSection(sectionIndex);

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
    auto virtualAddress = symbol->getAddress();

    if(knownLinkerBytes(symbol)) {
        LOG(1, "treating " << symbol->getName() << " as a special case");
        disassembleBlocks(true, function, readAddress, symbol->getSize(),
            virtualAddress);
        ChunkMutator m(function);  // recalculate cached values if necessary
        return function;
    }

    bool literal = false;
    size_t offset = 0;
    Symbol *mapping = nullptr;
    if(symbolList) {
        mapping = symbolList->findMappingBelowOrAt(symbol);
    }

    if(mapping) {
        LOG(10, "mapping symbol below " << symbol->getName()
            << " at " << std::hex << symbol->getAddress()
            << " - " << (symbol->getAddress() + symbol->getSize())
            << " is " << mapping->getName()
            << " #" << std::dec << mapping->getIndex());

        address_t end = symbol->getAddress() + symbol->getSize();
        literal = processMappingSymbol(mapping);
        while((mapping = symbolList->findMappingAbove(mapping))) {
            LOG(10, "    next mapping symbol is #"
                << std::dec << mapping->getIndex());
            if(end <= mapping->getAddress()) {
                auto size = symbol->getSize() - offset;
                disassembleBlocks(literal, function, readAddress + offset,
                    size, virtualAddress + offset);
                offset += size;
                break;
            }
            auto size = mapping->getAddress() - (symbol->getAddress() + offset);
            disassembleBlocks(literal, function, readAddress + offset,
                size, symbol->getAddress() + offset);
            offset += size;
            literal = processMappingSymbol(mapping);
        }
    }
    if(offset < symbol->getSize()) {
        disassembleBlocks(literal, function, readAddress + offset,
            symbol->getSize() - offset, virtualAddress + offset);
    }

    {
        ChunkMutator m(function);  // recalculate cached values if necessary
    }

    return function;
}

static void dump(IntervalTree &tree) {
    for(const Range &range : tree.getAllData()) {
        LOG(1, "start: " << std::hex
            << range.getStart() << " " << range.getSize());
    }
}

FunctionList *DisassembleAARCH64Function::linearDisassembly(
    const char *sectionName, DwarfUnwindInfo *dwarfInfo,
    SymbolList *dynamicSymbolList, RelocList *relocList) {

    auto section = elfMap->findSection(sectionName);
    if(!section) return nullptr;

    //TemporaryLogLevel tll("disasm", 10);

    address_t codeStart = section->getVirtualAddress();
    address_t codeEnd = section->getVirtualAddress() + section->getSize();

    std::vector<ElfSection *> sectionList;
    auto plt = elfMap->findSection(".plt");
    ElfXX_Ehdr *header = (ElfXX_Ehdr *)elfMap->getMap();
    ElfXX_Shdr *sheader
        = (ElfXX_Shdr *)(elfMap->getCharmap() + header->e_shoff);
    for(int i = 0; i < header->e_shnum; i ++) {
        ElfXX_Shdr *s = &sheader[i];
        if(s->sh_flags & SHF_EXECINSTR) {
            auto sec = elfMap->findSection(i);
            if(sec == plt) continue;
            sectionList.push_back(sec);
        }
    }

    for(auto s : sectionList) {
        LOG(10, "exec section: " << s->getName());
        codeStart = std::min(codeStart, s->getVirtualAddress());
        codeEnd = std::max(codeEnd, s->getVirtualAddress() + s->getSize());
    }

    Range codeRange(codeStart, codeEnd - codeStart);
    IntervalTree splitRanges(codeRange);
    splitRanges.add(codeRange);

    for(auto s : sectionList) {
        splitRanges.splitAt(s->getVirtualAddress());
        splitRanges.splitAt(s->getVirtualAddress() + s->getSize());
    }
    LOG(10, "initial section boundaries");
    IF_LOG(10) dump(splitRanges);

    // Find known functions from DWARF info
    for(auto it = dwarfInfo->fdeBegin(); it != dwarfInfo->fdeEnd(); it ++) {
        DwarfFDE *fde = *it;
        if(splitRanges.splitAt(fde->getPcBegin())) {
            LOG(10, "DWARF FDE at [" << std::hex << fde->getPcBegin() << ",+"
                << fde->getPcRange() << "]");
        }
        else {
            LOG(10, "FDE is out of bounds of .text section, skipping");
        }
    }

    LOG(10, "with DWARF");
    IF_LOG(10) dump(splitRanges);

    // Run first disassembly pass, to find obvious function boundaries
    splitRanges.splitAt(elfMap->getEntryPoint());

    LOG(10, "with DWARF + entryPoint");
    IF_LOG(10) dump(splitRanges);

    for(auto s : sectionList) {
        firstDisassemblyPass(s, splitRanges);
    }
    LOG(10, "with DWARF + entryPoint + first");
    IF_LOG(10) dump(splitRanges);

    splitByDynamicSymbols(dynamicSymbolList, splitRanges);
    LOG(10, "with DWARF + entryPoint + first + plt");
    IF_LOG(10) dump(splitRanges);

    splitByRelocations(relocList, splitRanges);
    LOG(10, "with DWARF + entryPoint + first + plt + reloc");
    IF_LOG(10) dump(splitRanges);

    finalDisassemblyPass(section, splitRanges);
    LOG(10, "with DWARF + entryPoint + first + plt + reloc + final");
    IF_LOG(10) dump(splitRanges);

    FunctionList *functionList = new FunctionList();
    for(auto s : sectionList) {
        LOG(10, "splitting into functions in " << s->getName());
        auto intervalList = splitRanges.findOverlapping(Range(
            s->getVirtualAddress(), s->getSize()));
        for(const auto& r : intervalList) {
            LOG0(10, "    " << r);
            if(auto sym = dynamicSymbolList->find(r.getStart())) {
                LOG(10, " ...from dynamic symbol");
                assert(sym->getSize() == r.getSize());
                auto function = this->function(sym, nullptr);
                functionList->getChildren()->add(function);
                function->setParent(functionList);
            } else {
                LOG(10, " ...fuzzy");
                size_t processed = 0;
                do {
                    Range tmp(r.getStart() + processed,
                        r.getSize() - processed);
                    auto function = fuzzyFunction(tmp, s);
                    processed += function->getSize() + 4;   // for next round
                    functionList->getChildren()->add(function);
                    function->setParent(functionList);
                } while (processed < r.getSize());
            }
        }
    }

    return functionList;
}

void DisassembleAARCH64Function::firstDisassemblyPass(ElfSection *section,
    IntervalTree &splitRanges) {

    address_t virtualAddress = section->getVirtualAddress();
    address_t readAddress = section->getReadAddress()
        + section->convertVAToOffset(virtualAddress);
    size_t readSize = section->getSize();

    for(size_t size = 0; size < readSize; ) {
        cs_insn *insn;
        size_t count = cs_disasm(handle.raw(),
            (const uint8_t *)readAddress + size,
            readSize - size,
            virtualAddress + size,
            0, &insn);
        for(size_t j = 0; j < count; j++) {
            auto ins = &insn[j];

            address_t target = 0;
            if(shouldSplitFunctionDueTo(ins, &target)) {
                splitRanges.splitAt(target);
            }
        }

        if(count > 0) {
            cs_free(insn, count);
            size += count * 4;
        }
        else {
            size += 4;
        }
    }
}

// this could be run multiple times until it converges
void DisassembleAARCH64Function::finalDisassemblyPass(ElfSection *section,
    IntervalTree &splitRanges) {

    for(auto const& range : splitRanges.getAllData()) {
        address_t virtualAddress = range.getStart();
        address_t readAddress = section->getReadAddress()
            + section->convertVAToOffset(virtualAddress);
        address_t readSize = range.getSize();

        for(size_t size = 0; size < readSize; ) {
            cs_insn *insn;
            size_t count = cs_disasm(handle.raw(),
                (const uint8_t *)readAddress + size,
                readSize - size,
                virtualAddress + size,
                0, &insn);
            for(size_t j = 0; j < count; j++) {
                auto ins = &insn[j];

                address_t target = 0;
                if(shouldSplitFunctionDueTo2(ins, virtualAddress,
                    virtualAddress + readSize, &target)) {

                    splitRanges.splitAt(target);
                }
            }

            if(count > 0) {
                cs_free(insn, count);
                size += count * 4;
            }
            else {
                size += 4;
            }
        }
    }
}

void DisassembleAARCH64Function::splitByDynamicSymbols(
    SymbolList *dynamicSymbolList, IntervalTree &splitRanges) {

    if(!dynamicSymbolList) return;
    for(auto sym : *dynamicSymbolList) {
        if(sym->getType() == Symbol::TYPE_FUNC
            && sym->getSectionIndex() != SHN_UNDEF) {

            splitRanges.splitAt(sym->getAddress());
            splitRanges.splitAt(sym->getAddress() + sym->getSize());
        }
    }
}

void DisassembleAARCH64Function::splitByRelocations(
    RelocList *relocList, IntervalTree &splitRanges) {

    if(!relocList) return;
    for(auto r : *relocList) {
        if(r->getType() == R_AARCH64_RELATIVE) {
            splitRanges.splitAt(r->getAddend());
        }
    }
}

Function *DisassembleAARCH64Function::fuzzyFunction(const Range &range,
    ElfSection *section) {

    address_t virtualAddress = section->getVirtualAddress();
    address_t readAddress = section->getReadAddress()
        + section->convertVAToOffset(virtualAddress);
    address_t intervalVirtualAddress = range.getStart();
    address_t intervalOffset = intervalVirtualAddress - virtualAddress;
    address_t intervalSize = range.getSize();

    Function *function = new Function(intervalVirtualAddress);

    PositionFactory *positionFactory = PositionFactory::getInstance();
    function->setPosition(
        positionFactory->makeAbsolutePosition(intervalVirtualAddress));

    disassembleBlocks(false, function, readAddress + intervalOffset,
        intervalSize, intervalVirtualAddress);

    {
        ChunkMutator m(function);  // recalculate cached values if necessary
    }

    return function;
}

void DisassembleAARCH64Function::disassembleBlocks(bool literal,
    Function *function, address_t readAddress, size_t readSize,
    address_t virtualAddress) {

    if(literal) {
        processLiterals(function, readAddress, readSize, virtualAddress);
    }
    else {
        DisassembleFunctionBase::disassembleBlocks(
            function, readAddress, readSize, virtualAddress);
    }
}

void DisassembleAARCH64Function::processLiterals(Function *function,
    address_t readAddress, size_t readSize, address_t virtualAddress) {

    LOG(10, "literals embedded in " << function->getName()
        << " at address 0x" << std::hex << virtualAddress);

    PositionFactory *positionFactory = PositionFactory::getInstance();

    Block *block = makeBlock(function, nullptr);

    Chunk *prevChunk = nullptr;
    if(function->getChildren()->getIterable()->getCount() > 0) {
        prevChunk = function->getChildren()->getIterable()->getLast();
    }

    size_t literalSize;
    for(size_t sz = 0; sz < readSize; sz += literalSize) {
        if(readSize - sz < 8) literalSize = 4;
        else literalSize = (virtualAddress + sz) & 0x7 ? 4 : 8;

        auto instr = new Instruction();
        std::string raw;
        raw.assign(reinterpret_cast<char *>(readAddress + sz), literalSize);
        SemanticImpl *li = nullptr;
        li = new LiteralInstruction();
        li->setData(raw);
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

bool DisassembleAARCH64Function::knownLinkerBytes(Symbol *symbol) {
    if(!strcmp(symbol->getName(), "buildsig")) return true;
    return false;
}

Function *DisassembleRISCVFunction::function(Symbol *symbol,
    SymbolList *symbolList) {

    LOG(1, "Disassembling function " << symbol->getName() << "(" << std::dec
        << symbol->getSize() << " bytes)");

    auto sectionIndex = symbol->getSectionIndex();
    auto section = elfMap->findSection(sectionIndex);

    PositionFactory *positionFactory = PositionFactory::getInstance();
    Function *function = new Function(symbol);

    address_t symbolAddress = symbol->getAddress();

    function->setPosition(
        positionFactory->makeAbsolutePosition(symbolAddress));

    auto readAddress =
        section->getReadAddress() + section->convertVAToOffset(symbolAddress);
    auto readSize = symbol->getSize();
    auto virtualAddress = symbol->getAddress();

    // XXX: this is a hack to work around a compiler/linker bug
    // sometimes the symbol sizes are 4 bytes too small.
    Symbol *nxt;
    const std::vector<int> offsets{2,4,6};
    for(auto off : offsets) {
        if(symbolList->find(virtualAddress + readSize) == nullptr
            && (nxt = symbolList->find(virtualAddress + readSize + off)) != nullptr) {

            if(nxt == symbol) {
                LOG(1, "Found negative-sized function, skipping this size increment.");
                continue;
            }

            LOG(1, "Increasing size of function \"" << symbol->getName() << "\"");
            LOG(1, "\tstarting at address 0x" << std::hex << virtualAddress);
            LOG(1, "\twhich normally has size " << std::dec << readSize);
            LOG(1, "\tfound symbol with name \"" << nxt->getName() << "\"");
            LOG(1, "\t\tat address 0x" << std::hex << (virtualAddress + readSize + 4));
            readSize += off;
            break;
        }
    }

    auto context = ParseOverride::getInstance()->makeContext(
        function->getSymbol()->getName());

    if(auto over = ParseOverride::getInstance()->getBlockBoundaryOverride(
        context)) {

        LOG(10, "Using parsing override!");

        disassembleCustomBlocks(function, readAddress, virtualAddress,
            over->getOverrideList());

    }
    else {
        disassembleBlocks(
            function, readAddress, readSize, virtualAddress);
    }

    {
        ChunkMutator m(function);  // recalculate cached values if necessary
    }

    return function;
}

FunctionList *DisassembleRISCVFunction::linearDisassembly(
    const char *sectionName, DwarfUnwindInfo *dwarfInfo,
    SymbolList *dynamicSymbolList, RelocList *relocList) {

    FunctionList *functionList = new FunctionList();

    assert(0); // Shouldn't ever be needed, we have symbols

    #if 0
    for(const Range &range : intervalList) {
        LOG(11, "Split into function " << range << " at section offset "
            << section->convertVAToOffset(range.getStart()));
        Function *function = fuzzyFunction(range, section);
        functionList->getChildren()->add(function);
        function->setParent(functionList);
    }
    #endif

    return functionList;
}


void DisassembleFunctionBase::disassembleBlocks(Function *function,
    address_t readAddress, size_t readSize, address_t virtualAddress) {

    PositionFactory *positionFactory = PositionFactory::getInstance();

    LOG(19, "disassemble 0x" << std::hex << readAddress << " size " << readSize
        << ", virtual address " << virtualAddress);
    #ifndef ARCH_RISCV
    cs_insn *insn;
    size_t count = cs_disasm(handle.raw(),
        (const uint8_t *)readAddress, readSize, virtualAddress, 0, &insn);
    #else
    auto insn = rv_disasm_buffer(rv64, virtualAddress,
        (const uint8_t *)readAddress, readSize);
    size_t count = insn.size();
    #endif

    Block *block = makeBlock(function, nullptr);

    for(size_t j = 0; j < count; j++) {
        auto ins = &insn[j];

        // check if this instruction ends the current basic block
        bool split = shouldSplitBlockAt(ins);

        // Create Instruction from cs_insn/rv_instr
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
        CLOG0(10, "fall-through function [%s]... "
            "adding basic block\n", function->getName().c_str());
        ChunkMutator(function, false).append(block);
    }
    if(block->getSize() == 0) {
        delete block;
    }

    if(function->getSize() < readSize) {
        LOG(1, "disassembly error? " << function->getName()
            << " " << function->getSize() << " < " << readSize);
    }

#ifdef ARCH_X86_64
    if(false) {
        size_t j = 0;
        for(auto b : CIter::children(function)) {
            for(auto i : CIter::children(b)) {
                InstrWriterGetData writer;
                i->getSemantic()->accept(&writer);
                std::string data = writer.get();

                auto ins = &insn[j++];
                bool different = false;
                if(ins->size != data.length()) different = true;
                else {
                    for(size_t z = 0; z < data.length(); z ++) {
                        if((unsigned char)ins->bytes[z] != (unsigned char)data[z]) {
                            different = true;
                            break;
                        }
                    }
                }

                if(different) {
                    LOG(1, "ERROR: reconstructed instruction differs from original:");

                    {
                        std::ostringstream stream;
                        stream << "original:      address: " << std::hex << ins->address << ", bytes:";
                        for(size_t i = 0; i < ins->size; i ++) {
                            stream << std::hex << " " << (unsigned char)ins->bytes[i];
                        }
                        LOG(1, stream.str());
                    }

                    {
                        std::ostringstream stream;
                        stream << "reconstructed: address: " << std::hex << i->getAddress() << ", bytes:";
                        for(size_t i = 0; i < data.length(); i ++) {
                            stream << std::hex << " " << (unsigned char)data[i];
                        }
                        LOG(1, stream.str());
                    }
                }
            }
        }
        for(size_t j = 0; j < count; j ++) {
        }
    }
#endif

    #ifndef ARCH_RISCV
    cs_free(insn, count);
    #endif
}

void DisassembleFunctionBase::disassembleCustomBlocks(Function *function,
    address_t readAddress, address_t virtualAddress,
    const std::vector<std::pair<address_t, size_t>> &blockBoundaries) {

    LOG(1, "disassembling function using custom block layout");

    PositionFactory *positionFactory = PositionFactory::getInstance();

    for(auto boundary : blockBoundaries) {
        if(boundary.second == 0) continue;

        // insert padding to function representation to make addresses line up
        if(boundary.first > function->getSize()) {
            size_t gap = boundary.first - function->getSize();
            LOG(10, "creating gap block of size 0x" << std::hex << gap);

            Block *gapBlock = makeBlock(function, nullptr);

#ifdef ARCH_X86_64
            for(size_t i = 0; i < gap; i ++) {
                // HLT instruction byte
                auto instr = Disassemble::instruction({0xf4},
                    false, function->getAddress() + function->getSize() + i);
                ChunkMutator(gapBlock, false).append(instr);
            }
#elif defined(ARCH_AARCH64)
            if((gap % 4) != 0) {
                LOG(1, "gap block size not multiple of 4!");
            }
            for(size_t i = 0; i < gap; i += 4) {
                // instruction bytes for nop:
                // 1F 20 03 D5
                auto instr = Disassemble::instruction({0x1f, 0x20, 0x03, 0xd5},
                    false, function->getAddress() + function->getSize() + i);
                ChunkMutator(gapBlock, false).append(instr);
            }
#elif defined(ARCH_RISCV)
            if((gap % 2) != 0) {
                LOG(1, "gap block size not multiple of 2!");
            }
            for(size_t i = 0; i < gap; i += 2) {
                // instruction bytes for nop:
                // 01 00
                auto instr = Disassemble::instruction({0x01, 0x00},
                    false, function->getAddress() + function->getSize() + i);
                ChunkMutator(gapBlock, false).append(instr);
            }
#else
    #error "Need to implement padding scheme for current architecture!"
#endif
            ChunkMutator(function, false).append(gapBlock);
        }

        LOG(19, "disassemble 0x" << std::hex << (readAddress+boundary.first)
            << " size " << boundary.second << ", virtual address "
            << (virtualAddress+boundary.first));


        #ifndef ARCH_RISCV
        cs_insn *insn;
        size_t count = cs_disasm(handle.raw(),
            (const uint8_t *)readAddress + boundary.first, boundary.second,
            virtualAddress + boundary.first, 0, &insn);
        #else
        auto insn = rv_disasm_buffer(rv64, virtualAddress + boundary.first,
            (const uint8_t *)readAddress + boundary.first, boundary.second);
        size_t count = insn.size();
        #endif

        if(count == 0) {
            LOG(1, "Disassembly error encountered in function ["
                << function->getName()
                << "] in custom block starting at offset 0x"
                << std::hex << boundary.first);
            continue;
        }

        Block *block = makeBlock(function, nullptr);

        // re-set starting position because we may have skipped bytes
        #if 0
        delete block->getPosition();
        block->setPosition(new AbsoluteOffsetPosition(block, boundary.first));
        /*block->setPosition(
            positionFactory->makePosition(block->getPreviousSibling(), block,
                                          boundary.first));*/
        #endif

        #if 0
        size_t boundaryOffset = 0;
        #endif
        for(size_t j = 0; j < count; j++) {
            auto ins = &insn[j];

            // check if this instruction ends the current basic block
            bool split = shouldSplitBlockAt(ins);

            // Create Instruction from cs_insn/rv_instr
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
            #if 0
            boundaryOffset += instr->getSize();
            #endif

            ChunkMutator(block, false).append(instr);
            if(split) {
                LOG(11, "split-instr in block: " << j+1);
                ChunkMutator(function, false).append(block);

                block = makeBlock(function, block);
                #if 0
                block->setPosition(
                    new AbsoluteOffsetPosition(block, boundary.first + boundaryOffset));
                #endif
            }
        }

        if(block->getSize() > 0) {
            CLOG0(10, "fall-through function [%s]... "
                "adding basic block\n", function->getName().c_str());
            ChunkMutator(function, false).append(block);
        }
        if(block->getSize() == 0) {
            delete block;
        }

        #ifndef ARCH_RISCV
        cs_free(insn, count);
        #endif
    }

    IF_LOG(10) {
        LOG(10, "before recalculation:");
        for(auto block : CIter::children(function)) {
            LOG(10, "    block address: " << std::hex << block->getAddress());
        }
    }

    // force block recalculation
    {
        ChunkMutator(function, true);
    }

    IF_LOG(10) {
        LOG(10, "before recalculation:");
        for(auto block : CIter::children(function)) {
            LOG(10, "    block address: " << std::hex << block->getAddress());
        }
    }
    IF_LOG(10) {
        LOG(10, "after recalculation:");
        for(auto block : CIter::children(function)) {
            LOG(10, "    block address: " << std::hex << block->getAddress());
        }
    }
}

Block *DisassembleFunctionBase::makeBlock(Function *function, Block *prev) {
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

bool DisassembleFunctionBase::shouldSplitBlockAt(cs_insn *ins) {
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
    else if(ins->id == ARM64_INS_BRK) { // special case (#0x3e8)
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

#ifdef ARCH_RISCV
bool DisassembleFunctionBase::shouldSplitBlockAt(rv_instr *ins) {

    // sb codec are the conditional branches
    if(ins->codec == rv_codec_sb) return true;

    const std::set<rv_op> cflow = {
        rv_op_j,
        rv_op_jr,
        rv_op_jal,
        rv_op_jalr,

        rv_op_c_j,
        rv_op_c_jr,
        rv_op_c_jal,
        rv_op_c_jalr,

        rv_op_ret
    };

    return cflow.count(ins->op) > 0;
}

#endif

bool DisassembleFunctionBase::shouldSplitFunctionDueTo(cs_insn *ins,
    address_t *target) {

#ifdef ARCH_X86_64
    if(cs_insn_group(handle.raw(), ins, X86_GRP_CALL)) {
        cs_x86 *x = &ins->detail->x86;
        cs_x86_op *op = &x->operands[0];
        if(x->op_count > 0 && op->type == X86_OP_IMM) {
            *target = op->imm;
            return true;
        }
    }
#elif defined(ARCH_AARCH64)
    if(ins->id == ARM64_INS_BL) {
        cs_arm64 *x = &ins->detail->arm64;
        cs_arm64_op *op = &x->operands[0];
        if(x->op_count > 0 && op->type == ARM64_OP_IMM) {
            *target = op->imm;
            return true;
        }
    }
    if(ins->id == ARM64_INS_B) {
        cs_arm64 *x = &ins->detail->arm64;
        cs_arm64_op *op = &x->operands[0];
        if(x->op_count == 1 && op->type == ARM64_OP_IMM) {
            address_t dest = op->imm;
            if(dest == ins->address + 4) {
                LOG(10, " strange uncoditional jump to next address");
                *target = dest;
                return true;
            }
        }
    }
#elif defined(ARCH_ARM)
    #error "Not yet implemented"
#elif defined(ARCH_RISCV)
    LOG(1, "shouldSplitFunctionDueTo NYI for RISCV");
#endif
    return false;
}

bool DisassembleFunctionBase::shouldSplitFunctionDueTo2(cs_insn *ins,
    address_t start, address_t end, address_t *target) {

#ifdef ARCH_AARCH64
    if(cs_insn_group(handle.raw(), ins, ARM64_GRP_JUMP)) {
        cs_arm64 *x = &ins->detail->arm64;
        cs_arm64_op *op = &x->operands[0];
        if(x->op_count > 0 && op->type == ARM64_OP_IMM) {
            address_t dest = op->imm;
            if(dest < start || end <= dest) {
                *target = dest;
                return true;
            }
        }
    }
#endif
    return false;
}
