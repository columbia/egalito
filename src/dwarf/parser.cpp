#include <cstdio>
#include <cstdlib>
#include <cassert>
#include "parser.h"
#include "entry.h"
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
    assert(cieIndex < cies.size());
    return &cies[cieIndex];
}

void DwarfParser::parse(address_t readAddress, address_t virtualAddress,
    size_t virtualSize) {

    DwarfCursor start(virtualAddress);
    DwarfCursor end(virtualAddress + virtualSize);
    uint64_t indexOfCIEinVector = 0;

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
            CommonInformationEntry cie(start, entryLength, length, indexOfCIEinVector, ehSectionStartAddress);

            cies.push_back(cie);
            cieMap.insert(std::make_pair(start.getBeginning(), indexOfCIEinVector++));
        }
        else {  // it's an FDE within the given CIE
            auto it = cieMap.find(startOfEntry.getCursor() - entryID);
            if(it != cieMap.end()) {
                uint64_t cieIndex = (*it).second;

                DwarfFDE *fde = parseFDE(start, cieIndex, readAddress, virtualAddress);

                /*FrameDescriptorEntry fde(start, length, entryID,
                    &cies[cieIndex], cieIndex, ehSectionStartAddress, ehSectionShAddr);*/

            }
            else {
                LOG(1, "WARNING: unknown CIE index in FDE definition");
            }
        }

        start = DwarfCursor(start.getBeginning() + entryLength);
    }
}

/************************
 * INSTRUCTION PARSING 
 * **********************/

#define OPCODE_LOG(format, ...) \
    CLOG(11, format, __VA_ARGS__)
using std::printf;  // hack for now
using std::exit;  // hack for now

static uint64_t dereferencePointer(uint64_t pointer) {
    return *(reinterpret_cast<uint64_t *>(pointer));
}

static uint64_t decodeExpression(DwarfCursor start, dwarf_state_t *state) {
    uint64_t length = start.nextUleb128();
    DwarfCursor end = start;
    end.skip(length);
    std::vector<uint64_t> evalStack;
    evalStack.reserve(100);

    while (start < end) {
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
                evalStack.push_back(state->registers[reg].offset);
                printf ("DW_OP_reg%ld", reg);
                break;

            case DW_OP_regx:
                reg = start.nextUleb128();
                //TODO: Not sure about the following operation
                //Using offsets for now, but might need to use values or
                //something else completely
                evalStack.push_back(state->registers[reg].offset);
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
                evalStack.push_back(state->registers[reg].offset + svalue);
                printf ("DW_OP_breg%ld (%s): %ld", reg, registerNames[reg].c_str(), svalue);
                break;

            case DW_OP_bregx:
                reg = start.nextUleb128();
                svalue = start.nextSleb128();
                //TODO: Not sure about the following operation
                //Using offsets for now, but might need to use values or
                //something else completely
                evalStack.push_back(state->registers[reg].offset + svalue);
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
                case 1:
                    value = start.next<uint8_t>();
                    break;
                case 2:
                    value = start.next<uint16_t>();
                    break;
                case 4:
                    value = start.next<uint32_t>();
                    break;
                case 8:
                    value = start.next<uint64_t>();
                    break;
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
        if (start < end)
        {
            printf("; ");
        }
    }
    return evalStack.back();
}

void DwarfParser::parseInstructions(DwarfCursor start, DwarfCursor end, CommonInformationEntry* cie, state_t *state, uint64_t cfaIp)
{
    const uint64_t codeAlignFactor = cie->getCodeAlignFactor();
    const uint64_t dataAlignFactor = cie->getDataAlignFactor();
    uint64_t ul, reg, registerOffset;
    int64_t l, ofs;
    uint64_t nextIp;

    memcpy(state, &(cie->state), sizeof(state_t));

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
            state->registers[op].type = DW_CFA_offset;
            state->registers[op].offset = registerOffset * dataAlignFactor;
            break;

        case DW_CFA_restore:
            printf ("  DW_CFA_restore: %s\n", getRegisterName(op).c_str());
            state->registers[op].type = cie->state.registers[op].type;
            state->registers[op].offset  = cie->state.registers[op].offset;
            break;

        case DW_CFA_set_loc:
            cfaIp = start.nextEncodedPointer<int64_t>(cie->getCodeEnc());
            printf ("  DW_CFA_set_loc: %08lx\n", cfaIp);
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
            state->registers[reg].type = DW_CFA_offset;
            state->registers[reg].offset = registerOffset * dataAlignFactor;
            break;

        case DW_CFA_val_offset:
            reg = start.nextUleb128();
            registerOffset = start.nextUleb128();
            printf("  DW_CFA_val_offset: %s at cfa%+ld\n",
                    getRegisterName(reg).c_str(),
                    registerOffset * dataAlignFactor);
            state->registers[reg].type = DW_CFA_val_offset;
            state->registers[reg].offset     = registerOffset * dataAlignFactor;
            break;

        case DW_CFA_restore_extended:
            reg = start.nextUleb128();
            printf("  DW_CFA_restore_extended: %s\n",
                    getRegisterName(reg).c_str());
            state->registers[reg].type = cie->state.registers[reg].type;
            state->registers[reg].offset = cie->state.registers[reg].offset;
            break;

        case DW_CFA_undefined:
            reg = start.nextUleb128();
            printf("  DW_CFA_undefined: %s\n",
                    getRegisterName(reg).c_str());
            state->registers[reg].type = DW_CFA_undefined;
            state->registers[reg].offset = 0;
            break;

        case DW_CFA_same_value:
            reg = start.nextUleb128();
            printf("  DW_CFA_same_value: %s\n",
                    getRegisterName(reg).c_str());
            state->registers[reg].type = DW_CFA_same_value;
            state->registers[reg].offset = 0;
            break;

        case DW_CFA_register:
            reg = start.nextUleb128();
            registerOffset = start.nextUleb128();
            printf("  DW_CFA_register: %s in %s\n",
                    getRegisterName(reg).c_str(), getRegisterName(registerOffset).c_str());
            state->registers[reg].type = DW_CFA_register;
            state->registers[reg].offset = registerOffset;
            break;

        case DW_CFA_remember_state: {
            printf("  DW_CFA_remember_state\n");
            auto tempState = new state_t();
            memcpy(tempState, state, sizeof(state_t));
            tempState->next = rememberedState;
            *rememberedState = tempState;
            break;
        }
        case DW_CFA_restore_state: {
            printf("  DW_CFA_restore_state\n");
            if(auto tempState = rememberedState) {
                rememberedState = tempState->next;
                memcpy(state, tempState, sizeof(state_t));
                delete tempState;
            }
            break;
        }

        case DW_CFA_def_cfa:
            state->cfaRegister = start.nextUleb128();
            state->cfaOffset = start.nextUleb128();
            state->cfaExpression = 0;
            printf("  DW_CFA_def_cfa: %s ofs %ld\n",
                    getRegisterName(state->cfaRegister).c_str(), state->cfaOffset);
            break;

        case DW_CFA_def_cfa_register:
            state->cfaRegister = start.nextUleb128();
            state->cfaExpression = 0;
            printf("  DW_CFA_def_cfa_register: %s\n",
                    getRegisterName(state->cfaRegister).c_str());
            break;

        case DW_CFA_def_cfa_offset:
            state->cfaOffset = start.nextUleb128();
            printf("  DW_CFA_def_cfa_offset: %ld\n", state->cfaOffset);
            break;

        case DW_CFA_nop:
            printf("  DW_CFA_nop\n");
            break;

        case DW_CFA_def_cfa_expression:
            //TODO: Complete this decoding
            printf ("  DW_CFA_def_cfa_expression (");
            decodeExpression(start, state);
            printf (")\n");
            state->cfaExpression = start.getBeginning() + start.getOffset();
            ul = start.nextUleb128();
            start.skip(ul);
            break;

        case DW_CFA_expression:
            reg = start.nextUleb128();
            state->registers[reg].type = DW_CFA_expression;
            state->registers[reg].offset = start.getBeginning() + start.getOffset();
            //TODO: Complete this decoding
            printf ("  DW_CFA_expression: %s (",
                    getRegisterName(reg).c_str());
            decodeExpression(start, state);
            printf (")\n");
            ul = start.nextUleb128();
            start.skip(ul);
            break;

        case DW_CFA_val_expression:
            reg = start.nextUleb128();
            //TODO: Complete this decoding
            printf ("  DW_CFA_val_expression: %s (",
                    getRegisterName(reg).c_str());
            decodeExpression(start, state);
            printf (")\n");
            ul = start.nextUleb128();
            state->registers[reg].type = DW_CFA_val_expression;
            start.skip(ul);
            break;

        case DW_CFA_offset_extended_sf:
            reg = start.nextUleb128();
            l = start.nextSleb128();
            printf("  DW_CFA_offset_extended_sf: %s at cfa%+ld\n",
                    getRegisterName(reg).c_str(),
                    l * dataAlignFactor);
            state->registers[reg].type = DW_CFA_offset;
            state->registers[reg].offset = l * dataAlignFactor;
            break;

        case DW_CFA_val_offset_sf:
            reg = start.nextUleb128();
            l = start.nextSleb128();
            printf("  DW_CFA_val_offset_sf: %s at cfa%+ld\n",
                    getRegisterName(reg).c_str(),
                    l * dataAlignFactor);
            state->registers[reg].type = DW_CFA_val_offset;
            state->registers[reg].offset = l * dataAlignFactor;
            break;

        case DW_CFA_def_cfa_sf:
            state->cfaRegister = start.nextUleb128();
            state->cfaOffset = start.nextSleb128();
            state->cfaOffset = state->cfaOffset * dataAlignFactor;
            state->cfaExpression = 0;
            printf("  DW_CFA_def_cfa_sf: %s ofs %ld\n",
                    getRegisterName(state->cfaRegister).c_str(), state->cfaOffset);
            break;

        case DW_CFA_def_cfa_offset_sf:
            state->cfaOffset = start.nextSleb128();
            state->cfaOffset = state->cfaOffset * dataAlignFactor;
            printf("  DW_CFA_def_cfa_offset_sf: %ld\n", state->cfaOffset);
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
            l = - start.nextUleb128();
            printf("  DW_CFA_GNU_negative_offset_extended: %s at cfa%+ld\n",
                    getRegisterName(reg).c_str(),
                    l * dataAlignFactor);
            state->registers[reg].type = DW_CFA_offset;
            state->registers[reg].offset = l * dataAlignFactor;
            break;

        default:
            printf("  DW_CFA_??? (User defined call frame opcode: %#x)\n", opcode);
            start = end;
        }
    }
}

/*********************************
 * Class CommonInformationEntry
 * ******************************/
CommonInformationEntry::CommonInformationEntry(DwarfCursor start, uint64_t entryLength, uint64_t length, uint64_t index, address_t ehSectionStartAddress)
{
    this->startAddress = start.getBeginning();
    this->cieId = 0;
    this->augmentationSectionLength = 0;
    this->personalityEncoding = 0;
    this->personalityEncodingRoutine = 0;
    this->codeEnc = 0;
    this->lsdaEnc = DW_EH_PE_omit;
    this->isSignal = false;
    this->entryLength = entryLength;
    this->length = length;
    this->index = index;
    parseCIE(start, ehSectionStartAddress);
}

void CommonInformationEntry::parseCIE(DwarfCursor start, address_t virtualAddress, uint64_t index) {
    DwarfCIE *cie = new DwarfCIE(start.getStart(), length, index);
    start >> version;

    if(version != 1 && version != 3) {
        LOG(1, "ERROR: Dwarf version number is not 1 or 3");
        return;
    }

    auto cieAugmentationString = start.nextString();

    codeAlignFactor = start.nextUleb128(); 
    dataAlignFactor = start.nextSleb128();

    retAddressReg = start.nextUleb128();

    if(*cieAugmentationString) {
        if(*cieAugmentationString != 'z') {
            LOG(1, "ERROR: Augmentation string should start with '\\0' or 'z'");
            return;
        }

        augmentationSectionLength = start.nextUleb128();

        for(uint8_t *ptr = cieAugmentationString + 1; *ptr; ptr ++) {
            switch(static_cast<char>(*ptr)) {
            case 'L':
                start >> lsdaEnc;
                break;
            case 'P':
                start >> personalityEncoding;
                personalityEncodingRoutine = start.nextEncodedPointer<uint64_t>(personalityEncoding);
                break;
            case 'R':
                start >> codeEnc;
                break;
            case 'S':
                isSignal = true;
                break;
            default:
                break;
            }
        }

        Augmentation *augmentation = new Augmentation(augmentationSectionLength);
    }

    /********************
     * DEBUG
     * ******************/
    printf ("\n%08lx %016lx %08lx CIE\n",
            startAddress - ehSectionStartAddress, length, static_cast<uint64_t>(0));
    printf ("  Version:               %d\n", getVersion());
    printf ("  Augmentation:          \"%s\"\n", getCieAugmentationString());
    printf ("  Code alignment factor: %lu\n", getCodeAlignFactor());
    printf ("  Data alignment factor: %ld\n", getDataAlignFactor());
    printf ("  Return address column: %lu\n", getRetAddressReg());
    printf("\n");

    parseInstructions(start, DwarfCursor(start.getBeginning() + entryLength), this, &(this->state), 0); 
}

#if 0
FrameDescriptorEntry::FrameDescriptorEntry(DwarfCursor start, uint64_t entryLength, uint64_t length, uint32_t ciePointer,  CommonInformationEntry* cie, uint64_t cieIndex, address_t ehSectionStartAddress, address_t ehSectionShAddr)
{
    this->startAddress = start.getBeginning();
    this->entryLength = entryLength;
    this->length = length;
    this->ciePointer = ciePointer;
    this->cieIndex = cieIndex;

    assert(cie->getIndex() == cieIndex);
    parseFDE(start, cie, ehSectionStartAddress, ehSectionShAddr);
}
#endif

DwarfFDE *DwarfParser::parseFDE(DwarfCursor start, uint64_t cieIndex,
    address_t readAddress, address_t virtualAddress) {

    DwarfCIE *cie = getCIE(cieIndex);
    DwarfFDE *fde = new DwarfFDE(start.getStart(), length, cieIndex);

    fde->setPcBegin(start.nextEncodedPointer<int64_t>(
        cie->getCodeEnc()) + virtualAddress);
    fde->setPcRange(start.nextEncodedPointer<uint64_t>(
        cie->getCodeEnc() & 0x0F));

    if(cie->doFDEsHaveAugmentationSection()) {
        size_t augLength = start.nextUleb128();

        // will be set to 0 if the LSDA encoding is DW_EH_PE_omit
        lsdaPointer = start.nextEncodedPointer<uint64_t>(cie->getLsdaEnc());
    }

    /********************
     * DEBUG
     * ******************/
    printf ("\n%08lx %016lx %08lx FDE cie=%08lx pc=%016lx..%016lx\n",
            (startAddress - ehSectionStartAddress), length, static_cast<uint64_t>(ciePointer),
            (cie->getCieStartAddress() - ehSectionStartAddress),
            (getPcBegin() - ehSectionStartAddress), 
            (getPcBegin() - ehSectionStartAddress) + getPcRange());
    parseInstructions(start, DwarfCursor(start.getBeginning() + entryLength), cie, &(this->state), (getPcBegin() - ehSectionStartAddress)); 

    return fde;
}
