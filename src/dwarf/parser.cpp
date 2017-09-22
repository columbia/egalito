#include <cstdio>
#include <cstdlib>
#include <cassert>
#include "parser.h"
#include "entry.h"
#include "state.h"
#include "platform.h"
#include "elf/elfmap.h"
#include "log/log.h"

DwarfParser::DwarfParser(ElfMap *elfMap) {
    ElfSection *section = elfMap->findSection(".eh_frame");

    if(section) {
        parse(section->getReadAddress(), section->getVirtualAddress(),
            section->getSize());
    }
    else {
        LOG(0, "WARNING: no .eh_frame section present in ELF file!");
    }
}

DwarfCIE *DwarfParser::getCIE(uint64_t cieIndex) {
    assert(cieIndex < cieList.size());
    return cieList[cieIndex];
}

void DwarfParser::parse(address_t readAddress, address_t virtualAddress,
    size_t virtualSize) {

    DwarfCursor start(virtualAddress);
    DwarfCursor end(virtualAddress + virtualSize);

    LOG(10, "Contents of the .eh_frame section:");

    while(start < end) {
        uint64_t length = start.next<uint32_t>();
        uint64_t entryLength = length + 4;
        if(length == 0xfffffffful) {
            // the length is in the next 8 bytes
            start >> length;
            entryLength = length + 8;
        }

        if(length == 0) {
            CLOG(10, "\n%08lx ZERO terminator\n\n", start.getStart() - virtualAddress);
            break;
        }

        DwarfCursor startOfEntry(start.getCursor());
        uint32_t entryID = start.next<uint32_t>();

        if(entryID == 0) {  // it's a CIE
            const uint64_t cieIndex = cieList.size();
            DwarfCIE *cie = parseCIE(start, readAddress, virtualAddress,
                length, cieIndex);

            cieList.push_back(cie);
            cieMap[start.getStart()] = cieIndex;
        }
        else {  // it's an FDE within the given CIE
            auto it = cieMap.find(startOfEntry.getCursor() - entryID);
            if(it != cieMap.end()) {
                const uint64_t cieIndex = (*it).second;
                DwarfFDE *fde = parseFDE(start, cieIndex, readAddress, virtualAddress);

                fdeList.push_back(fde);
            }
            else {
                LOG(1, "WARNING: unknown CIE index in FDE definition");
            }
        }

        start = DwarfCursor(start.getStart() + entryLength);
    }
}

#define OPCODE_LOG(format, ...) \
    CLOG(11, format, __VA_ARGS__)
using std::printf;  // hack for now
using std::exit;  // hack for now

static uint64_t dereferencePointer(uint64_t pointer) {
    return *(reinterpret_cast<uint64_t *>(pointer));
}

static uint64_t decodeExpression(DwarfCursor start, DwarfState *state) {
    uint64_t length = start.nextUleb128();
    DwarfCursor end = start;
    end.skip(length);
    std::vector<uint64_t> evalStack;
    evalStack.reserve(100);

    while(start < end) {
        uint8_t opcode = start.next<uint8_t>();
        int64_t svalue;
        uint64_t value;
        uint64_t reg;
        switch (opcode) {
        case DW_OP_addr:
            start >> value;
            printf ("DW_OP_addr: %lx",
                    value);
            evalStack.push_back(value);
            break;

        case DW_OP_deref:
            value = evalStack.back();
            evalStack.pop_back();
            evalStack.push_back(dereferencePointer(value));
            printf ("DW_OP_deref");
            break;

        case DW_OP_const1u:
            value = start.next<uint8_t>();
            evalStack.push_back(value);
            printf ("DW_OP_const1u: %lu", value);
            break;
        case DW_OP_const1s:
            svalue = start.next<int8_t>();
            evalStack.push_back(svalue);
            printf ("DW_OP_const1s: %ld", svalue);
            break;
        case DW_OP_const2u:
            value = start.next<uint16_t>();
            evalStack.push_back(value);
            printf ("DW_OP_const2u: %lu", value);
            break;
        case DW_OP_const2s:
            svalue = start.next<int16_t>();
            evalStack.push_back(svalue);
            printf ("DW_OP_const2s: %ld", svalue);
            break;
        case DW_OP_const4u:
            value = start.next<uint32_t>();
            evalStack.push_back(value);
            printf ("DW_OP_const4u: %lu", value);
            break;
        case DW_OP_const4s:
            svalue = start.next<int32_t>();
            evalStack.push_back(svalue);
            printf ("DW_OP_const4s: %ld", svalue);
            break;
        case DW_OP_const8u:
            value = start.next<uint64_t>();
            evalStack.push_back(value);
            printf ("DW_OP_const8u: %lu %lu", value & 0xFFFFFFFF00000000, value & 0x00000000FFFFFFFF);
            break;
        case DW_OP_const8s:
            svalue = (int32_t)start.next<uint64_t>();
            evalStack.push_back(svalue);
            printf ("DW_OP_const8s: %ld %ld", svalue & 0xFFFFFFFF00000000, svalue & 0x00000000FFFFFFFF);
            break;
        case DW_OP_constu:
            value = start.nextUleb128();
            evalStack.push_back(value);
            printf ("DW_OP_constu: %lu", value);
            break;
        case DW_OP_consts:
            svalue = start.nextSleb128();
            evalStack.push_back(svalue);
            printf ("DW_OP_consts: %ld", svalue);
            break;

        case DW_OP_dup:
            value = evalStack.back();
            evalStack.push_back(value);
            printf ("DW_OP_dup");
            break;

        case DW_OP_drop:
            evalStack.pop_back();
            printf ("DW_OP_drop");
            break;

        case DW_OP_over:
            value = evalStack[evalStack.size() - 2];
            evalStack.push_back(value);
            printf ("DW_OP_over");
            break;

        case DW_OP_pick:
            reg = start.next<uint8_t>();
            value = evalStack[evalStack.size() - 1 - reg];
            evalStack.push_back(value);
            printf ("DW_OP_pick: %ld", (uint64_t)reg);
            break;

        case DW_OP_swap:
            value = evalStack[evalStack.size() - 1];
            evalStack[evalStack.size() - 1] = evalStack[evalStack.size() - 2];
            evalStack[evalStack.size() - 2] = value;
            printf ("DW_OP_swap");
            break;

        case DW_OP_rot:
            value = evalStack[evalStack.size() - 1];
            evalStack[evalStack.size() - 1] = evalStack[evalStack.size() - 2];
            evalStack[evalStack.size() - 2] = evalStack[evalStack.size() - 3];
            evalStack[evalStack.size() - 3] = value;
            printf ("DW_OP_rot");
            break;

        case DW_OP_xderef:
            value = evalStack.back();
            evalStack.pop_back();
            evalStack.push_back(dereferencePointer(value));
            printf ("DW_OP_xderef");
            break;

        case DW_OP_abs:
            svalue = evalStack.back();
            if ( svalue < 0 )
            {
                evalStack.back() = -svalue;
            }
            printf ("DW_OP_abs");
            break;

        case DW_OP_and:
            value = evalStack.back(); evalStack.pop_back();
            evalStack.back() &= value;
            printf ("DW_OP_and");
            break;

        case DW_OP_div:
            svalue = evalStack.back(); evalStack.pop_back();
            evalStack.back() = evalStack.back() / svalue;
            printf ("DW_OP_div");
            break;

        case DW_OP_minus:
            svalue = evalStack.back(); evalStack.pop_back();
            evalStack.back() = evalStack.back() - svalue;
            printf ("DW_OP_minus");
            break;

        case DW_OP_mod:
            svalue = evalStack.back(); evalStack.pop_back();
            evalStack.back() = evalStack.back() % svalue;
            printf ("DW_OP_mod");
            break;

        case DW_OP_mul:
            svalue = evalStack.back(); evalStack.pop_back();
            evalStack.back() = evalStack.back() * svalue;
            printf ("DW_OP_mul");
            break;

        case DW_OP_neg:
            evalStack.back() =  0 - evalStack.back();
            printf ("DW_OP_neg");
            break;

        case DW_OP_not:
            svalue = evalStack.back();
            evalStack.back() =  ~svalue;
            printf ("DW_OP_not");
            break;

        case DW_OP_or:
            value = evalStack.back(); evalStack.pop_back();
            evalStack.back() |= value;
            printf ("DW_OP_or");
            break;

        case DW_OP_plus:
            value = evalStack.back(); evalStack.pop_back();
            evalStack.back() += value;
            printf ("DW_OP_plus");
            break;

        case DW_OP_plus_uconst:
            // pop stack, add uelb128 constant, push result
            value = start.nextUleb128();
            evalStack.back() += value;
            printf ("DW_OP_plus_uconst: %lu", value);
            break;

        case DW_OP_shl:
            value = evalStack.back(); evalStack.pop_back();
            evalStack.back() = evalStack.back() << value;
            printf ("DW_OP_shl");
            break;

        case DW_OP_shr:
            value = evalStack.back(); evalStack.pop_back();
            evalStack.back() = evalStack.back() >> value;
            printf ("DW_OP_shr");
            break;

        case DW_OP_shra:
            value = evalStack.back(); evalStack.pop_back();
            svalue = evalStack.back();
            evalStack.back() = svalue >> value;
            printf ("DW_OP_shra");
            break;

        case DW_OP_xor:
            value = evalStack.back(); evalStack.pop_back();
            evalStack.back() ^= value;
            printf ("DW_OP_xor");
            break;

        case DW_OP_skip:
            svalue = start.next<int16_t>();
            start.skip(svalue);
            printf ("DW_OP_skip: %ld", svalue);
            break;

        case DW_OP_bra:
            svalue = start.next<int16_t>();
            if(evalStack.size() > 0) {
                evalStack.pop_back();
                start.skip(svalue);
            }
            printf ("DW_OP_bra: %ld", svalue);
            break;

        case DW_OP_eq:
            value = evalStack.back(); evalStack.pop_back();
            evalStack.back() = (evalStack.back() == value);
            printf ("DW_OP_eq");
            break;
        case DW_OP_ge:
            value = evalStack.back(); evalStack.pop_back();
            evalStack.back() = (evalStack.back() >= value);
            printf ("DW_OP_ge");
            break;
        case DW_OP_gt:
            value = evalStack.back(); evalStack.pop_back();
            evalStack.back() = (evalStack.back() > value);
            printf ("DW_OP_gt");
            break;
        case DW_OP_le:
            value = evalStack.back(); evalStack.pop_back();
            evalStack.back() = (evalStack.back() <= value);
            printf ("DW_OP_le");
            break;
        case DW_OP_lt:
            value = evalStack.back(); evalStack.pop_back();
            evalStack.back() = (evalStack.back() < value);
            printf ("DW_OP_lt");
            break;
        case DW_OP_ne:
            value = evalStack.back(); evalStack.pop_back();
            evalStack.back() = (evalStack.back() != value);
            printf ("DW_OP_ne");
            break;

        case DW_OP_lit0:
        case DW_OP_lit1:
        case DW_OP_lit2:
        case DW_OP_lit3:
        case DW_OP_lit4:
        case DW_OP_lit5:
        case DW_OP_lit6:
        case DW_OP_lit7:
        case DW_OP_lit8:
        case DW_OP_lit9:
        case DW_OP_lit10:
        case DW_OP_lit11:
        case DW_OP_lit12:
        case DW_OP_lit13:
        case DW_OP_lit14:
        case DW_OP_lit15:
        case DW_OP_lit16:
        case DW_OP_lit17:
        case DW_OP_lit18:
        case DW_OP_lit19:
        case DW_OP_lit20:
        case DW_OP_lit21:
        case DW_OP_lit22:
        case DW_OP_lit23:
        case DW_OP_lit24:
        case DW_OP_lit25:
        case DW_OP_lit26:
        case DW_OP_lit27:
        case DW_OP_lit28:
        case DW_OP_lit29:
        case DW_OP_lit30:
        case DW_OP_lit31:
            value = opcode - DW_OP_lit0;
            evalStack.push_back(value);
            printf ("DW_OP_lit%ld", value);
            break;

        case DW_OP_reg0:
        case DW_OP_reg1:
        case DW_OP_reg2:
        case DW_OP_reg3:
        case DW_OP_reg4:
        case DW_OP_reg5:
        case DW_OP_reg6:
        case DW_OP_reg7:
        case DW_OP_reg8:
        case DW_OP_reg9:
        case DW_OP_reg10:
        case DW_OP_reg11:
        case DW_OP_reg12:
        case DW_OP_reg13:
        case DW_OP_reg14:
        case DW_OP_reg15:
        case DW_OP_reg16:
        case DW_OP_reg17:
        case DW_OP_reg18:
        case DW_OP_reg19:
        case DW_OP_reg20:
        case DW_OP_reg21:
        case DW_OP_reg22:
        case DW_OP_reg23:
        case DW_OP_reg24:
        case DW_OP_reg25:
        case DW_OP_reg26:
        case DW_OP_reg27:
        case DW_OP_reg28:
        case DW_OP_reg29:
        case DW_OP_reg30:
        case DW_OP_reg31:
            reg = opcode - DW_OP_reg0;
            //TODO: Not sure about the following operation
            //Using offsets for now, but might need to use values or
            //something else completely
            evalStack.push_back(state->get(reg).getOffset());
            printf ("DW_OP_reg%ld", reg);
            break;

        case DW_OP_regx:
            reg = start.nextUleb128();
            //TODO: Not sure about the following operation
            //Using offsets for now, but might need to use values or
            //something else completely
            evalStack.push_back(state->get(reg).getOffset());
            printf ("DW_OP_regx: %lu", reg);
            break;          

        case DW_OP_breg0:
        case DW_OP_breg1:
        case DW_OP_breg2:
        case DW_OP_breg3:
        case DW_OP_breg4:
        case DW_OP_breg5:
        case DW_OP_breg6:
        case DW_OP_breg7:
        case DW_OP_breg8:
        case DW_OP_breg9:
        case DW_OP_breg10:
        case DW_OP_breg11:
        case DW_OP_breg12:
        case DW_OP_breg13:
        case DW_OP_breg14:
        case DW_OP_breg15:
        case DW_OP_breg16:
        case DW_OP_breg17:
        case DW_OP_breg18:
        case DW_OP_breg19:
        case DW_OP_breg20:
        case DW_OP_breg21:
        case DW_OP_breg22:
        case DW_OP_breg23:
        case DW_OP_breg24:
        case DW_OP_breg25:
        case DW_OP_breg26:
        case DW_OP_breg27:
        case DW_OP_breg28:
        case DW_OP_breg29:
        case DW_OP_breg30:
        case DW_OP_breg31:
            reg = opcode - DW_OP_breg0;
            svalue = start.nextSleb128();
            //TODO: Not sure about the following operation
            //Using offsets for now, but might need to use values or
            //something else completely
            evalStack.push_back(state->get(reg).getOffset() + svalue);
            printf ("DW_OP_breg%ld (%s): %ld", reg, shortRegisterName(reg), svalue);
            break;

        case DW_OP_bregx:
            reg = start.nextUleb128();
            svalue = start.nextSleb128();
            //TODO: Not sure about the following operation
            //Using offsets for now, but might need to use values or
            //something else completely
            evalStack.push_back(state->get(reg).getOffset() + svalue);
            printf ("DW_OP_bregx: %lu %ld", reg, svalue);
            break;

        case DW_OP_fbreg:
            //TODO:FATAL
            printf("DW_OP_fbreg is not supported");
            exit(1);
            break;

        case DW_OP_piece:
            //TODO:FATAL
            printf("DW_OP_piece is not supported");
            exit(1);
            break;

        case DW_OP_deref_size:
            // pop stack, dereference, push result
            value = evalStack.back(); evalStack.pop_back();
            printf ("DW_OP_deref_size: %lu", value);
            switch (start.next<uint8_t>()) {
            case 1: value = start.next<uint8_t>(); break;
            case 2: value = start.next<uint16_t>(); break;
            case 4: value = start.next<uint32_t>(); break;
            case 8: value = start.next<uint64_t>(); break;
            default:
                //TODO:FATAL
                printf("Invalid size in DW_OP_deref_size");
                exit(1);
            }
            evalStack.push_back(value);
            break;

        case DW_OP_xderef_size:
        case DW_OP_nop:
        case DW_OP_push_object_address:
        case DW_OP_call2:
        case DW_OP_call4:
        case DW_OP_call_ref:
        default:
            //TODO:FATAL
            printf("DW_OP_* is not supported");
            exit(1);
        }
        if(start < end) {
            printf("; ");
        }
    }
    return evalStack.back();
}

DwarfState *DwarfParser::parseInstructions(DwarfCursor start, DwarfCursor end,
    DwarfCIE *cie, uint64_t cfaIp) {

    DwarfState *state = new DwarfState(*cie->getState());

    const uint64_t codeAlignFactor = cie->getCodeAlignFactor();
    const int64_t dataAlignFactor = cie->getDataAlignFactor();
    uint64_t ul, reg, registerOffset;
    int64_t l, ofs;
    uint64_t nextIp;

    while(start < end) {
        uint8_t opcode;
        start >> opcode;

        uint64_t op = opcode & 0x3f;

        if(opcode & 0xc0) {
            opcode &= 0xc0;
        }

        switch (opcode) {
        case DW_CFA_advance_loc:
            nextIp = cfaIp + op * codeAlignFactor; 
            printf("  DW_CFA_advance_loc: %ld to %016lx\n", op * codeAlignFactor, nextIp);
            cfaIp = nextIp;
            break;

        case DW_CFA_offset:
            registerOffset = start.nextUleb128();
            printf("  DW_CFA_offset: %s at cfa%+ld\n", getRegisterName(op).c_str(), registerOffset * dataAlignFactor);
            state->set(op, DW_CFA_offset, registerOffset * dataAlignFactor);
            break;

        case DW_CFA_restore:
            printf ("  DW_CFA_restore: %s\n", getRegisterName(op).c_str());
            state->set(op, cie->getState()->get(op));
            break;

        case DW_CFA_set_loc:
            if(cie->getAugmentation()) {
                cfaIp = start.nextEncodedPointer<int64_t>(
                    cie->getAugmentation()->getCodeEnc());
                printf ("  DW_CFA_set_loc: %08lx\n", cfaIp);
            }
            break;

        case DW_CFA_advance_loc1:
            ofs = start.next<uint8_t>();
            nextIp = cfaIp + ofs * codeAlignFactor;

            printf("  DW_CFA_advance_loc1: %ld to %016lx\n",
                    ofs * codeAlignFactor,
                    nextIp);
            cfaIp = nextIp;
            break;

        case DW_CFA_advance_loc2:
            ofs = start.next<uint16_t>();
            nextIp = cfaIp + ofs * codeAlignFactor;

            printf("  DW_CFA_advance_loc2: %ld to %016lx\n",
                    ofs * codeAlignFactor,
                    nextIp);
            cfaIp = nextIp;
            break;

        case DW_CFA_advance_loc4:
            ofs = start.next<uint32_t>();
            nextIp = cfaIp + ofs * codeAlignFactor;

            printf("  DW_CFA_advance_loc4: %ld to %016lx\n",
                    ofs * codeAlignFactor,
                    nextIp);
            cfaIp = nextIp;
            break;

        case DW_CFA_offset_extended:
            reg = start.nextUleb128();
            registerOffset = start.nextUleb128();
            printf("  DW_CFA_offset_extended: %s at cfa%+ld\n",
                    getRegisterName(reg).c_str(),
                    registerOffset * dataAlignFactor);
            state->set(reg, DW_CFA_offset, registerOffset * dataAlignFactor);
            break;

        case DW_CFA_val_offset:
            reg = start.nextUleb128();
            registerOffset = start.nextUleb128();
            printf("  DW_CFA_val_offset: %s at cfa%+ld\n",
                    getRegisterName(reg).c_str(),
                    registerOffset * dataAlignFactor);
            state->set(reg, DW_CFA_val_offset, registerOffset * dataAlignFactor);
            break;

        case DW_CFA_restore_extended:
            reg = start.nextUleb128();
            printf("  DW_CFA_restore_extended: %s\n",
                    getRegisterName(reg).c_str());
            state->set(reg, cie->getState()->get(reg));
            break;

        case DW_CFA_undefined:
            reg = start.nextUleb128();
            printf("  DW_CFA_undefined: %s\n",
                    getRegisterName(reg).c_str());
            state->set(reg, DW_CFA_undefined, 0);
            break;

        case DW_CFA_same_value:
            reg = start.nextUleb128();
            printf("  DW_CFA_same_value: %s\n",
                    getRegisterName(reg).c_str());
            state->set(reg, DW_CFA_same_value, 0);
            break;

        case DW_CFA_register:
            reg = start.nextUleb128();
            registerOffset = start.nextUleb128();
            printf("  DW_CFA_register: %s in %s\n",
                    getRegisterName(reg).c_str(), getRegisterName(registerOffset).c_str());
            state->set(reg, DW_CFA_register, registerOffset);
            break;

        case DW_CFA_remember_state: {
            printf("  DW_CFA_remember_state\n");
            auto tempState = new DwarfState(*state);
            tempState->setNext(rememberedState);
            *rememberedState = *tempState;
            break;
        }
        case DW_CFA_restore_state: {
            printf("  DW_CFA_restore_state\n");
            if(auto tempState = rememberedState) {
                rememberedState = tempState->getNext();
                *state = *tempState;  // copy data
                delete tempState;
            }
            break;
        }

        case DW_CFA_def_cfa:
            state->setCfaRegister(start.nextUleb128());
            state->setCfaOffset(start.nextUleb128());
            state->setCfaExpression(0);
            printf("  DW_CFA_def_cfa: %s ofs %ld\n",
                getRegisterName(state->getCfaRegister()).c_str(),
                state->getCfaOffset());
            break;

        case DW_CFA_def_cfa_register:
            state->setCfaRegister(start.nextUleb128());
            state->setCfaExpression(0);
            printf("  DW_CFA_def_cfa_register: %s\n",
                getRegisterName(state->getCfaRegister()).c_str());
            break;

        case DW_CFA_def_cfa_offset:
            state->setCfaOffset(start.nextUleb128());
            printf("  DW_CFA_def_cfa_offset: %ld\n", state->getCfaOffset());
            break;

        case DW_CFA_nop:
            printf("  DW_CFA_nop\n");
            break;

        case DW_CFA_def_cfa_expression:
            //TODO: Complete this decoding
            printf("  DW_CFA_def_cfa_expression (");
            decodeExpression(start, state);
            printf(")\n");
            state->setCfaExpression(start.getCursor());
            ul = start.nextUleb128();
            start.skip(ul);
            break;

        case DW_CFA_expression:
            reg = start.nextUleb128();
            state->set(reg, DW_CFA_expression, start.getCursor());
            //TODO: Complete this decoding
            printf("  DW_CFA_expression: %s (",
                getRegisterName(reg).c_str());
            decodeExpression(start, state);
            printf(")\n");
            ul = start.nextUleb128();
            start.skip(ul);
            break;

        case DW_CFA_val_expression:
            reg = start.nextUleb128();
            //TODO: Complete this decoding
            printf("  DW_CFA_val_expression: %s (",
                    getRegisterName(reg).c_str());
            decodeExpression(start, state);
            printf (")\n");
            ul = start.nextUleb128();
            state->set(reg, DW_CFA_val_expression, state->get(reg).getOffset());
            start.skip(ul);
            break;

        case DW_CFA_offset_extended_sf:
            reg = start.nextUleb128();
            l = start.nextSleb128();
            printf("  DW_CFA_offset_extended_sf: %s at cfa%+ld\n",
                    getRegisterName(reg).c_str(),
                    l * dataAlignFactor);
            state->set(reg, DW_CFA_offset, l * dataAlignFactor);
            break;

        case DW_CFA_val_offset_sf:
            reg = start.nextUleb128();
            l = start.nextSleb128();
            printf("  DW_CFA_val_offset_sf: %s at cfa%+ld\n",
                    getRegisterName(reg).c_str(),
                    l * dataAlignFactor);
            state->set(reg, DW_CFA_val_offset, l * dataAlignFactor);
            break;

        case DW_CFA_def_cfa_sf:
            state->setCfaRegister(start.nextUleb128());
            state->setCfaOffset(start.nextSleb128() * dataAlignFactor);
            state->setCfaExpression(0);
            printf("  DW_CFA_def_cfa_sf: %s ofs %ld\n",
                getRegisterName(state->getCfaRegister()).c_str(),
                state->getCfaOffset());
            break;

        case DW_CFA_def_cfa_offset_sf:
            state->setCfaOffset(start.nextSleb128() * dataAlignFactor);
            printf("  DW_CFA_def_cfa_offset_sf: %ld\n", state->getCfaOffset());
            break;

        case DW_CFA_MIPS_advance_loc8:
            ofs = start.next<uint64_t>();
            printf("  DW_CFA_MIPS_advance_loc8: %ld to %016lx\n",
                    ofs * codeAlignFactor,
                    cfaIp + ofs * codeAlignFactor);
            cfaIp += ofs * codeAlignFactor;
            break;

        case DW_CFA_GNU_window_save:
            printf("  DW_CFA_GNU_window_save\n");
            break;

        case DW_CFA_GNU_args_size:
            ul = start.nextUleb128();
            printf("  DW_CFA_GNU_args_size: %ld\n", ul);
            break;

        case DW_CFA_GNU_negative_offset_extended:
            reg = start.nextUleb128();
            l = -start.nextUleb128();
            printf("  DW_CFA_GNU_negative_offset_extended: %s at cfa%+ld\n",
                    getRegisterName(reg).c_str(),
                    l * dataAlignFactor);
            state->set(reg, DW_CFA_offset, l * dataAlignFactor);
            break;

        default:
            printf("  DW_CFA_??? (User defined call frame opcode: %#x)\n", opcode);
            start = end;
        }
    }

    return state;
}

DwarfCIE *DwarfParser::parseCIE(DwarfCursor start, address_t readAddress,
    address_t virtualAddress, uint64_t length, uint64_t index) {

    DwarfCIE *cie = new DwarfCIE(start.getStart(), length, index);

    uint8_t version = start.next<uint8_t>();
    if(version != 1 && version != 3) {
        LOG(1, "ERROR: Dwarf version number is not 1 or 3");
        return nullptr;
    }

    auto cieAugmentationString = start.nextString();
    cie->setCodeAlignFactor(start.nextUleb128());
    cie->setDataAlignFactor(start.nextSleb128());
    cie->setRetAddressReg(start.nextUleb128());

    if(*cieAugmentationString) {
        if(*cieAugmentationString != 'z') {
            LOG(1, "ERROR: Augmentation string should start with '\\0' or 'z'");
            return nullptr;
        }

        auto augmentation = new DwarfCIE::Augmentation();

        const auto augmentationLength = start.nextUleb128();  // not used
        for(uint8_t *ptr = cieAugmentationString + 1; *ptr; ptr ++) {
            switch(static_cast<char>(*ptr)) {
            case 'P':
                augmentation->setPersonalityEncoding(start.next<uint8_t>());
                augmentation->setPersonalityEncodingRoutine(
                    start.nextEncodedPointer<uint64_t>(augmentation->getPersonalityEncoding()));
                break;
            case 'R':
                augmentation->setCodeEnc(start.next<uint8_t>());
                break;
            case 'L':
                augmentation->setLsdaEnc(start.next<uint8_t>());
                break;
            case 'S':
                augmentation->setIsSignal(true);
                break;
            default:
                LOG(11, "Unknown DWARF LSDA encoding character '" << *ptr << "'");
                break;
            }
        }

        cie->setAugmentation(augmentation);
    }

    printf("\n%08lx %016lx %08lx CIE\n",
        start.getStart() - readAddress, length, 0ul);
    printf("  Version:               %d\n", version);
    printf("  Augmentation:          \"%s\"\n", cieAugmentationString);
    printf("  Code alignment factor: %lu\n", cie->getCodeAlignFactor());
    printf("  Data alignment factor: %ld\n", cie->getDataAlignFactor());
    printf("  Return address column: %lu\n", cie->getRetAddressReg());
    printf("\n");

    DwarfCursor where{start.getStart() + entryLength};
    auto state = parseInstructions(start, where, cie, 0);
    cie->setState(state);
    return cie;
}

DwarfFDE *DwarfParser::parseFDE(DwarfCursor start, uint64_t cieIndex,
    address_t readAddress, address_t virtualAddress) {

    DwarfCIE *cie = getCIE(cieIndex);
    DwarfFDE *fde = new DwarfFDE(start.getStart(), length, cieIndex);

    fde->setPcBegin(start.nextEncodedPointer<int64_t>(
        cie->getCodeEnc()) + virtualAddress);
    fde->setPcRange(start.nextEncodedPointer<uint64_t>(
        cie->getCodeEnc() & 0x0F));

    if(cie->doFDEsHaveAugmentationSection()) {
        const auto augmentationLength = start.nextUleb128();  // not used

        // will be set to 0 if the LSDA encoding is DW_EH_PE_omit
        const auto lsdaPointer = start.nextEncodedPointer<uint64_t>(cie->getLsdaEnc());

        fde->setAugmentation(new DwarfFDE::Augmentation(lsdaPointer));
    }

    printf("\n%08lx %016lx %08lx FDE cie=%08lx pc=%016lx..%016lx\n",
        start.getStart() - readAddress, length,
        static_cast<uint64_t>(fde->getCiePointer()),
        cie->getStartAddress() - readAddress,
        fde->getPcBegin() - readAddress, 
        fde->getPcBegin() - readAddress + fde->getPcRange());
    DwarfCursor where{start.getStart() + entryLength};
    auto state = parseInstructions(start, where, cie, fde->getPcBegin() - readAddress);
    fde->setState(state);
    return fde;
}
