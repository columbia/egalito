#include <cassert>
#include "jumptabledetection.h"
#include "analysis/walker.h"
#include "analysis/usedef.h"
#include "analysis/usedefutil.h"
#include "chunk/concrete.h"
#include "elf/elfspace.h"
#include "instr/concrete.h"
#include "operation/find.h"

#include "log/log.h"
#include "log/temp.h"

void JumptableDetection::detect(Module *module) {
    //TemporaryLogLevel tll("analysis", 11);
    for(auto f : CIter::functions(module)) {
        //TemporaryLogLevel tll2("analysis", 11, f->hasName("vfprintf"));
        detect(f);
        //IF_LOG(11) std::cout.flush();
    }
}

void JumptableDetection::detect(Function *function) {
    if(containsIndirectJump(function)) {
        ControlFlowGraph cfg(function);
        UDConfiguration config(&cfg);
        UDRegMemWorkingSet working(function, &cfg);
        UseDef usedef(&config, &working);

        IF_LOG(10) cfg.dump();
        IF_LOG(10) cfg.dumpDot();

        SccOrder order(&cfg);
        order.genFull(0);
        usedef.analyze(order.get());

        detect(&working);
    }
}

void JumptableDetection::detect(UDRegMemWorkingSet *working) {
#ifdef ARCH_X86_64
    typedef TreePatternBinary<TreeNodeAddition,
        TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>,
        TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>
    > MakeJumpTargetForm1;

    // __strcmp_ssse3
    typedef TreePatternBinary<TreeNodeAddition,
        TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>,
        TreePatternBinary<TreeNodeMultiplication,
            TreePatternCapture<
                TreePatternTerminal<TreeNodePhysicalRegister>>,
            TreePatternCapture<TreePatternTerminal<TreeNodeConstant>>
        >
    > MakeJumpTargetForm2;

    for(auto block : CIter::children(working->getFunction())) {
        auto instr = block->getChildren()->getIterable()->getLast();
        auto s = instr->getSemantic();
        if(auto ij = dynamic_cast<IndirectJumpInstruction *>(s)) {
            auto mode = ij->getAssembly()->getAsmOperands()->getMode();
            if(mode != AssemblyOperands::MODE_REG) continue;
            LOG(10, "indirect jump at 0x" << std::hex << instr->getAddress());
            auto state = working->getState(instr);
            IF_LOG(10) state->dumpState();
            int reg = X86Register::convertToPhysical(ij->getRegister());

            JumptableInfo info(working->getCFG(), working, state);
            auto parser = [&](UDState *s, TreeCapture& cap) {
                return parseJumptable(s, cap, &info);
            };
            auto parser2 = parser;

            LOG(10, "trying MakeJumpTargetForm1");
            FlowUtil::searchUpDef<MakeJumpTargetForm1>(state, reg, parser);
            if(info.valid) {
                makeDescriptor(instr, &info);
                continue;
            }

            LOG(10, "trying MakeJumpTargetForm2");
            FlowUtil::searchUpDef<MakeJumpTargetForm2>(state, reg, parser2);
            if(info.valid) {
                makeDescriptor(instr, &info);
                continue;
            }

            LOG(10, "trying C Form");
            parseOldCJumptable(state, reg, &info);
        }
    }
#elif defined(ARCH_AARCH64)
    typedef TreePatternBinary<TreeNodeAddition,
        TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>,
        TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>
    > MakeJumpTargetForm1;

    typedef TreePatternBinary<TreeNodeAddition,
        TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>,
            TreePatternBinary<TreeNodeLogicalShiftLeft,
                TreePatternCapture<
                    TreePatternTerminal<TreeNodePhysicalRegister>>,
                TreePatternCapture<TreePatternTerminal<TreeNodeConstant>>
            >
    > MakeJumpTargetForm2;

    for(auto block : CIter::children(working->getFunction())) {
        auto instr = block->getChildren()->getIterable()->getLast();
        auto s = instr->getSemantic();
        if(dynamic_cast<IndirectJumpInstruction *>(s)) {
            LOG(10, "indirect jump at 0x" << std::hex << instr->getAddress());
            auto state = working->getState(instr);
            IF_LOG(10) state->dumpState();

            JumptableInfo info(working->getCFG(), working, state);
            auto parser = [&](UDState *s, TreeCapture& cap) {
                return parseJumptable(s, cap, &info);
            };

            LOG(10, "trying MakeJumpTargetForm1");
            auto assembly = s->getAssembly();
            auto op0 = assembly->getAsmOperands()->getOperands()[0].reg;
            int reg = AARCH64GPRegister::convertToPhysical(op0);
            FlowUtil::searchUpDef<MakeJumpTargetForm1>(state, reg, parser);
            if(info.valid) {
                makeDescriptor(instr, &info);
                continue;
            }

            LOG(10, "trying MakeJumpTargetForm2");
            FlowUtil::searchUpDef<MakeJumpTargetForm2>(state, reg, parser);
            if(info.valid) {
                makeDescriptor(instr, &info);
                continue;
            }
        }
    }
#elif defined(ARCH_RISCV)
    /* Example jump table use:
        auipc   a4,0x0
        addi    a4,a4,418 # 10600 <__libc_csu_fini+0x6>
            a4: jump table base
        slli    a5,a5,0x2
            a5: jump table offset
        add     a5,a5,a4
            a5: jump table offset + jump table base = address of jump table entry
        lw      a5,0(a5)
            a5: jump table entry
        add     a5,a5,a4
            a5: jump table entry + jump table base
        jr      a5



            +
                jump table entry
                +
                    TreeNodeAddress
                    TreeNodeConstant

     */


    /*typedef TreePatternBinary<TreeNodeAddition,
        TreePatternBinary<TreeNodeAddition,
            TreePatternAny,
            TreePatternAny>,
            //TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>,
            //TreePatternCapture<TreePatternTerminal<TreeNodeConstant>>
            //>
        TreePatternCapture<TreePatternAny>
        // TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>
        > MakeJumpTargetForm1;*/
    //typedef TreePatternAny MakeJumpTargetForm1;
    
    typedef TreePatternBinary<TreeNodeAddition,
        TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>,
        TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>
        > MakeJumpTargetForm1;

    for(auto block : CIter::children(working->getFunction())) {
        auto instr = block->getChildren()->getIterable()->getLast();
        auto s = instr->getSemantic();
        if(auto ij = dynamic_cast<IndirectJumpInstruction *>(s)) {
            LOG(10, "***** indirect jump at 0x" << std::hex << instr->getAddress());
            CLOG(10, "register: %d", ij->getRegister());

            auto state = working->getState(instr);
            // state->dumpState();

            JumptableInfo info(working->getCFG(), working, state);
            auto parser1 = [&](UDState *s, TreeCapture& cap) {
                return parseJumptable(s, cap, &info);
            };

            LOG(10, "trying MakeJumpTargetForm1");
            auto assembly = s->getAssembly();
            auto reg = assembly->getAsmOperands()->getOperands()[0].value.reg;
            FlowUtil::searchUpDef<MakeJumpTargetForm1>(state, reg, parser1);

            if(info.valid) {
                LOG(10, "valid jump table descriptor!");
                makeDescriptor(instr, &info);
                continue;
            }
            
        }

    }

    /*typedef TreePatternBinary<TreeNodeAddition,
        TreePatternCapture<TreePatternTerminal<*/
    // assert(0); // XXX: no idea
#endif
}

bool JumptableDetection::containsIndirectJump(Function *function) const {
    for(auto block : CIter::children(function)) {
        auto instr = block->getChildren()->getIterable()->getLast();
        auto s = instr->getSemantic();
        if(dynamic_cast<IndirectJumpInstruction *>(s)) {
            return true;
        }
    }
    return false;
}

bool JumptableDetection::parseJumptable(UDState *state, TreeCapture& cap,
    JumptableInfo *info) {

#ifdef ARCH_X86_64
    auto regTree1 = dynamic_cast<TreeNodePhysicalRegister *>(cap.get(0));
    auto regTree2 = dynamic_cast<TreeNodePhysicalRegister *>(cap.get(1));
#elif defined(ARCH_AARCH64)
    auto regTree1 = dynamic_cast<TreeNodePhysicalRegister *>(cap.get(0));
    auto regTree2 = dynamic_cast<TreeNodePhysicalRegister *>(cap.get(1));
#elif defined(ARCH_RISCV)
    auto regTree1 = dynamic_cast<TreeNodePhysicalRegister *>(cap.get(1));
    auto regTree2 = dynamic_cast<TreeNodePhysicalRegister *>(cap.get(0));
#endif

    LOG(10, "parseJumptable");

    bool found = false;
    address_t targetBase;
    std::tie(found, targetBase)
        = parseBaseAddress(state, regTree1->getRegister());
    if(found) {
        LOG(10, "index 0: matches table base form");
        found = parseTableAccess(state, regTree2->getRegister(), info);
    }
    if(!found) {
        std::tie(found, targetBase)
            = parseBaseAddress(state, regTree2->getRegister());
        if(targetBase > 0) {
            LOG(10, "index 1: matches table base form");
            found = parseTableAccess(state, regTree1->getRegister(), info);
        }
    }
    if(found) {
        LOG(10, "Found jump table at 0x" << std::hex << targetBase);
        info->valid = true;
        info->targetBase = targetBase;
        #ifdef ARCH_RISCV
        LOG(1, "XXX: assuming tableBase and targetBase are equal");
        info->tableBase = targetBase;
        #endif
        return true;
    }
    return false;
}

#ifdef ARCH_X86_64
void JumptableDetection::parseOldCJumptable(UDState *state, int reg,
    JumptableInfo *info) {

    LOG(10, "parseOldCJumptable " << std::hex
        << state->getInstruction()->getAddress());
    IF_LOG(10) state->dumpState();


    // printf: ascii --> jump_table[] --(index)--> stepi_jumps[] --> target
    typedef TreePatternBinary<TreeNodeAddition,
        TreePatternPhysicalRegisterIs<X86Register::BP>,
        TreePatternTerminal<TreeNodeConstant>
    > MemForm1;

    typedef TreePatternBinary<TreeNodeAddition,
        TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>,
        TreePatternUnary<TreeNodeDereference,
            TreePatternCapture<MemForm1>
        >
    > MakeJumpTargetForm3;

    auto parser3 = [&, reg](UDState *s, TreeCapture& cap) {
        auto regTree = dynamic_cast<TreeNodePhysicalRegister *>(
            cap.get(0));
        if(regTree->getRegister() == reg) {
            parseJumptableWithIndexTable(s, reg, info);
            if(!info->valid) return false;

            // targetBase == tableBase is only guaranteed for compiler
            // generated x86 jump tables
            address_t targetBase = 0;
            MemLocation mem(cap.get(1));
            for(auto ref : s->getMemRef(reg)) {
                for(auto& def : ref->getMemDefList()) {
                    if(mem != MemLocation(def.second)) continue;

                    LOG(10, "base pushed at "
                        << std::hex << ref->getInstruction()->getAddress());
                    bool found = false;
                    std::tie(found, targetBase)
                        = parseBaseAddress(ref, def.first);
                    if(found) {
                        LOG(10, "    targetBase found! "
                            << std::hex << targetBase);
                        info->targetBase = targetBase;
                        makeDescriptor(state->getInstruction(), info);

                        // there can be more than one
                        info->valid = false;
                        return false;
                    }
                }
            }
        }
        return false;
    };

    FlowUtil::searchUpDef<MakeJumpTargetForm3>(state, reg, parser3);
}

bool JumptableDetection::parseJumptableWithIndexTable(UDState *state,
    int reg, JumptableInfo *info) {

    typedef TreePatternCapture<TreePatternUnary<TreeNodeDereference,
        TreePatternBinary<TreeNodeAddition,
            TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>,
            TreePatternBinary<TreeNodeMultiplication,
                TreePatternCapture<
                    TreePatternTerminal<TreeNodePhysicalRegister>>,
                TreePatternCapture<TreePatternTerminal<TreeNodeConstant>>
            >
        >
    >> TableAccessForm1;

    LOG(10, "parseJumptableWithIndexTable " << std::hex
        << state->getInstruction()->getAddress());
    IF_LOG(10) state->dumpState();


    bool found = false;
    auto jumpTableParser = [&, info](UDState *js, TreeCapture& cap) {
        auto regTree1 = dynamic_cast<TreeNodePhysicalRegister *>(cap.get(1));
        auto regTree2 = dynamic_cast<TreeNodePhysicalRegister *>(cap.get(2));
        auto scaleTree = dynamic_cast<TreeNodeConstant *>(cap.get(3));

        address_t address;
        std::tie(found, address)
            = parseBaseAddress(js, regTree1->getRegister());
        if(found) {
            LOG(10, "JUMP TABLE ACCESS FOUND!");
            info->tableBase = address;
            info->scale = scaleTree->getValue();

            auto reg = regTree2->getRegister();
            LOG(10, "trying to find index table from "
                << std::hex << js->getInstruction()->getAddress()
                << " for " << std::dec << reg);

            for(auto s : js->getRegRef(reg)) {
                if(getBoundFromIndexTable(s, reg, info)) {
                    LOG(10, "getBoundFromIndexTable matches in "
                        << s->getInstruction()->getParent()->getParent()
                            ->getName());
                    break;
                }
            }
        }
        return found;
    };


    found = false;
    FlowUtil::searchUpDef<TableAccessForm1>(state, reg, jumpTableParser);
    if(!found) return false;

    info->valid = true;
    return true;
}
#endif

void JumptableDetection::makeDescriptor(Instruction *instruction,
    const JumptableInfo *info) {

    auto working = info->working;
    auto it = tableMap.find(instruction);
    if(it != tableMap.end()) {
        bool exists = false;
        for(auto d : it->second) {
            if(d->getInstruction() == instruction
                && d->getAddress() == info->tableBase
                && d->getTargetBaseLink()->getTargetAddress()
                    == info->targetBase
                && d->getScale() == static_cast<int>(info->scale)
                //&& d->getEntries() == info->entries
                ) {
                exists = true;
                break;
            }
        }
        if(exists) return;
    }

    auto jtd = new JumpTableDescriptor(working->getFunction(), instruction);
    jtd->setAddress(info->tableBase);
    Link *link = nullptr;
    if(info->tableBase == info->targetBase) {
        link = LinkFactory::makeDataLink(module, info->targetBase, true);
    }
    else {
        // even for X86_64, jump table base != target base for hand-written
        // jump tables
        auto function
            = dynamic_cast<Function *>(instruction->getParent()->getParent());
        auto target = ChunkFind().findInnermostAt(function, info->targetBase);
        if(target) {
            link = LinkFactory::makeNormalLink(target, true, false);
        }
        else {
            link = module->getMarkerList()->createTableJumpTargetMarkerLink(
                    instruction, instruction->getSize(), module, false);
        }
    }
    assert(link);
    jtd->setTargetBaseLink(link);
    jtd->setScale(info->scale);
    jtd->setEntries(info->entries);

    auto contentSection =
        module->getDataRegionList()->findDataSectionContaining(info->tableBase);
    assert(contentSection);
    jtd->setContentSection(contentSection);
    tableList.push_back(jtd);

    LOG(10, "jump table jump at "
        << std::hex << info->jumpState->getInstruction()->getAddress());
    LOG(10, "descriptor:" << jtd);
    LOG(10, "baseAddress = " << std::hex << info->tableBase);
    LOG(10, "targetBaseAddress = " << std::hex << info->targetBase);
    LOG(10, "scale = " << std::dec << info->scale);
    LOG(10, "entries = " << std::dec << info->entries);

    tableMap[instruction].push_back(jtd);
}

bool JumptableDetection::parseTableAccess(UDState *state, int reg,
    JumptableInfo *info) {

#ifdef ARCH_X86_64
    typedef TreePatternCapture<TreePatternUnary<TreeNodeDereference,
        TreePatternBinary<TreeNodeAddition,
            TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>,
            TreePatternBinary<TreeNodeMultiplication,
                TreePatternCapture<
                    TreePatternTerminal<TreeNodePhysicalRegister>>,
                TreePatternCapture<TreePatternTerminal<TreeNodeConstant>>
            >
        >
    >> TableAccessForm1;  // typical jump table

    typedef TreePatternCapture<TreePatternUnary<TreeNodeDereference,
        TreePatternBinary<TreeNodeAddition,
            TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>,
            TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>
        >
    >> TableAccessForm2;

    typedef TreePatternCapture<TreePatternUnary<TreeNodeDereference,
        TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>
    >> IndexDerefForm;

    TreeNodeDereference *deref = nullptr;
    int derefReg = -1;
    auto indexParser = [&, info](UDState *s, TreeCapture& cap) {
        if(auto d = dynamic_cast<TreeNodeDereference *>(cap.get(0))) {
            if(auto regTree = dynamic_cast<TreeNodePhysicalRegister *>(cap.get(1))) {
                derefReg = regTree->getRegister();
            }
            deref = d;
        }
        LOG(1, "    looks like DEREF! " << deref);
        return deref != nullptr;
    };

    bool found = false;
    auto parser = [&, info](UDState *s, TreeCapture& cap) {
        auto regTree1 = dynamic_cast<TreeNodePhysicalRegister *>(cap.get(1));
        auto scaleTree = dynamic_cast<TreeNodeConstant *>(cap.get(3));

        address_t address;
        std::tie(found, address)
            = parseBaseAddress(s, regTree1->getRegister());
        if(found) {
            auto regTree2 = dynamic_cast<TreeNodePhysicalRegister *>(cap.get(2));
            FlowUtil::searchUpDef<IndexDerefForm>(s, reg, indexParser);

            LOG(10, "TABLE ACCESS FOUND! deref=" << deref);
            info->tableBase = address;
            info->scale = scaleTree->getValue();
            if(!deref) {
                parseBound(s, regTree2->getRegister(), info);
            }
            else {
                parseBoundDeref(s, deref, regTree2->getRegister(), info);
            }
            return true;
        }
        return false;
    };

    LOG(10, "[TableAccess] looking for reference in 0x" << std::hex
        << state->getInstruction()->getAddress()
        << " register " << std::dec << reg);
    IF_LOG(10) state->dumpState();

    LOG(10, "    trying TableAccessForm1");
    FlowUtil::searchUpDef<TableAccessForm1>(state, reg, parser);
    if(found) {
        return true;
    }
    LOG(10, "    trying TableAccessForm2");
    FlowUtil::searchUpDef<TableAccessForm2>(state, reg, parser);
    if(found) {
        return true;
    }
    return false;
#elif defined(ARCH_AARCH64)
    typedef TreePatternCapture<TreePatternUnary<TreeNodeDereference,
        TreePatternBinary<TreeNodeAddition,
            TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>,
            TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>
        >
    >> TableAccessForm1;

    typedef TreePatternCapture<TreePatternUnary<TreeNodeDereference,
        TreePatternBinary<TreeNodeAddition,
            TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>,
            TreePatternBinary<TreeNodeLogicalShiftLeft,
                TreePatternCapture<
                    TreePatternTerminal<TreeNodePhysicalRegister>>,
                TreePatternCapture<TreePatternTerminal<TreeNodeConstant>>
            >
        >
    >> TableAccessForm2;

    bool found = false;
    auto parser = [&, info](UDState *s, TreeCapture& cap) {
        auto regTree1 = dynamic_cast<TreeNodePhysicalRegister *>(cap.get(1));
        auto regTree2 = dynamic_cast<TreeNodePhysicalRegister *>(cap.get(2));

        address_t address;
        std::tie(found, address)
            = parseBaseAddress(s, regTree1->getRegister());
        if(found) {
            LOG(10, "JUMPTABLE FOUND!");
            info->tableBase = address;

            auto deref = dynamic_cast<TreeNodeDereference *>(cap.get(0));
            info->scale = deref->getWidth();

            parseBound(s, regTree2->getRegister(), info);
            return true;
        }
        return false;
    };

    LOG(10, "[TableAccess] looking for reference in 0x" << std::hex
        << state->getInstruction()->getAddress()
        << " register " << std::dec << reg);
    IF_LOG(10) state->dumpState();

    LOG(10, "    trying TableAccessForm1");
    FlowUtil::searchUpDef<TableAccessForm1>(state, reg, parser);
    if(found) {
        return true;
    }
    LOG(10, "    trying TableAccessForm2");
    FlowUtil::searchUpDef<TableAccessForm2>(state, reg, parser);
    if(found) {
        return true;
    }
    LOG(10, "        not found");
    return false;
#elif defined(ARCH_RISCV)
    typedef TreePatternBinary<TreeNodeLogicalShiftLeft,
        TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>,
        TreePatternCapture<TreePatternTerminal<TreeNodeConstant>>
        > DoubleShiftFirstForm;
    typedef TreePatternBinary<TreeNodeLogicalShiftRight,
        TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>,
        TreePatternCapture<TreePatternTerminal<TreeNodeConstant>>
        > DoubleShiftSecondForm;
    typedef TreePatternBinary<TreeNodeLogicalShiftLeft,
        TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>,
        TreePatternCapture<TreePatternTerminal<TreeNodeConstant>>
        > ShiftForm;

    typedef TreePatternBinary<TreeNodeAddition,
        TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>,
        TreePatternTerminal<TreeNodePhysicalRegister>
        > AddForm;

    typedef TreePatternUnary<TreeNodeDereference,
        TreePatternBinary<TreeNodeAddition,
            TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>,
            TreePatternCapture<TreePatternTerminal<TreeNodeConstant>>>
        > LoadForm;

    int doubleshift_first_amount;
    bool found_shift = false;
    bool found_add = false;
    bool found_load = false;

    auto doubleshift_first_parser = [&](UDState *s, TreeCapture &cap) {
        LOG(10, "found doubleshift first form");
        doubleshift_first_amount =
            static_cast<TreeNodeConstant *>(cap.get(1))->getValue();
        return true;
    };

    auto doubleshift_second_parser = [&](UDState *s, TreeCapture &cap) {
        LOG(10, "found doubleshift second form");
        doubleshift_first_amount = -1;

        FlowUtil::searchUpDef<DoubleShiftFirstForm>(s,
            static_cast<TreeNodePhysicalRegister *>(cap.get(0))->getRegister(),
            doubleshift_first_parser);

        if(doubleshift_first_amount == -1) return false;

        int delta = doubleshift_first_amount
            - static_cast<TreeNodeConstant *>(cap.get(1))->getValue();
        if(delta != 2) {
            LOG(1, "XXX: found doubleshift other than 2, maybe not jump table?");
            return false;
        }

        info->scale = 4;

        found_shift = true;
        return true;
    };

    auto shift_parser = [&](UDState *s, TreeCapture &cap) {
        LOG(1, "found shift form");

        if(static_cast<TreeNodeConstant *>(cap.get(1))->getValue() != 2) {
            LOG(1, "XXX: found shift other than 2, probably not a jump table?");
            return false;
        }
        info->scale = 4; // XXX: should actually be shift amount

        // rely on limit heuristics from elsewhere (jumptable adjacency, etc.)

        found_shift = true;
        return true;
    };

    auto add_parser = [&](UDState *s, TreeCapture &cap) {
        found_shift = false;
        LOG(1, "found add form");

        FlowUtil::searchUpDef<ShiftForm>(s,
            static_cast<TreeNodePhysicalRegister *>(cap.get(0))->getRegister(),
            shift_parser);
        if(!found_shift) {
            FlowUtil::searchUpDef<DoubleShiftSecondForm>(s,
                static_cast<TreeNodePhysicalRegister *>(
                    cap.get(0))->getRegister(),
                doubleshift_second_parser);
        }
        // XXX: assume that scale is 4 if no shift found
        if(!found_shift) {
            LOG(1, "XXX: found add w/o shift, assuming jump table w/scale 4");
            info->scale = 4;
        }
        found_add = true;
        return found_add;
    };

    auto load_parser = [&](UDState *s, TreeCapture &cap) {
        found_add = false;
        LOG(1, "found load form");

        // search for add form
        if(static_cast<TreeNodeConstant *>(cap.get(1))->getValue() != 0) {
            LOG(1, "XXX: found non-zero load @0x"
                << std::hex << s->getInstruction()->getAddress()
                << "? probably not a jump table");
            return false;
        }
        FlowUtil::searchUpDef<AddForm>(s,
            static_cast<TreeNodePhysicalRegister *>(cap.get(0))->getRegister(),
            add_parser);
        if(found_add) found_load = true;

        return found_load;
    };

    FlowUtil::searchUpDef<LoadForm>(state, reg, load_parser);

    return found_load;
#endif
}

auto JumptableDetection::parseBaseAddress(UDState *state, int reg)
    -> std::tuple<bool, address_t> {

    LOG(10, "[TableBase] looking for reference in 0x" << std::hex
        << state->getInstruction()->getAddress()
        << " register " << std::dec << reg);
    IF_LOG(10) state->dumpState();

#ifdef ARCH_X86_64
    typedef TreePatternBinary<TreeNodeAddition,
        TreePatternCapture<TreePatternRegisterIs<X86_REG_RIP>>,
        TreePatternCapture<TreePatternTerminal<TreeNodeConstant>>
    > BaseAddressForm;

    address_t addr = 0;
    bool found = false;
    auto parser = [&](UDState *s, TreeCapture& cap) {
        auto ripTree = dynamic_cast<TreeNodeRegisterRIP *>(cap.get(0));
        auto dispTree = dynamic_cast<TreeNodeConstant *>(cap.get(1));
        addr = dispTree->getValue() + ripTree->getValue();
        found = true;
        return true;
    };
    FlowUtil::searchUpDef<BaseAddressForm>(state, reg, parser);
    if(found) {
        return std::make_tuple(true, addr);
    }

    std::tie(found, addr) = parseSavedAddress(state, reg);
    if(found) {
        return std::make_tuple(true, addr);
    }

    std::tie(found, addr) = parseMovedAddress(state, reg);
    if(found) {
        return std::make_tuple(true, addr);
    }

    return std::make_tuple(false, 0);
#elif defined(ARCH_AARCH64)
    typedef TreePatternCapture<
        TreePatternTerminal<TreeNodeAddress>
    > BaseAddressForm;

    address_t addr = 0;
    bool found = false;
    auto parser = [&](UDState *s, TreeCapture& cap) {
        auto pageTree = dynamic_cast<TreeNodeAddress *>(cap.get(0));
        addr = pageTree->getValue();
        found = true;
        return true;
    };
    FlowUtil::searchUpDef<BaseAddressForm>(state, reg, parser);
    if(found) {
        return std::make_tuple(true, addr);
    }

    std::tie(found, addr) = parseComputedAddress(state, reg);
    if(found) {
        return std::make_tuple(true, addr);
    }
    return parseSavedAddress(state, reg);
#elif defined(ARCH_RISCV)
    // looking for auipc / addi combo
    typedef TreePatternCapture<TreePatternTerminal<TreeNodeAddress>> AuipcForm;
    typedef TreePatternBinary<TreeNodeAddition,
        TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>,
        TreePatternCapture<TreePatternTerminal<TreeNodeConstant>>
    > AddiForm;
    
    address_t auipc_addr = 0;
    bool found_auipc = false;
    address_t addr = 0;
    bool found = false;

    auto auipc_parser = [&](UDState *s, TreeCapture &cap) {
        LOG(1, "found auipc form");
        auipc_addr = static_cast<TreeNodeAddress *>(cap.get(0))->getValue();
        found_auipc = true;
        return true;
    };

    auto parser = [&](UDState *s, TreeCapture& cap) {
        LOG(1, "found addition form");
        found_auipc = false;
        FlowUtil::searchUpDef<AuipcForm>(s,
            static_cast<TreeNodePhysicalRegister *>(cap.get(0))->getRegister(),
            auipc_parser);
        if(!found_auipc) return false;
        addr =
            auipc_addr
            + static_cast<TreeNodeConstant *>(cap.get(1))->getValue();
        found = true;
        return true;
    };

    FlowUtil::searchUpDef<AddiForm>(state, reg, parser);

    if(found) {
        return std::make_tuple(true, addr);
    }
    else return std::make_tuple(false, 0);
#endif
}

auto JumptableDetection::parseSavedAddress(UDState *state, int reg)
    -> std::tuple<bool, address_t> {

    typedef TreePatternUnary<TreeNodeDereference,
        TreePatternCapture<TreePatternBinary<TreeNodeAddition,
            TreePatternTerminal<TreeNodePhysicalRegister>,
            TreePatternTerminal<TreeNodeConstant>>
        >
    > LoadForm;

    address_t addr = 0;
    bool found = false;
    auto parser = [&](UDState *s, TreeCapture& cap) {
        MemLocation loadLoc(cap.get(0));
        for(auto& ss : s->getMemRef(reg)) {
            for(const auto& mem : ss->getMemDefList()) {
                MemLocation storeLoc(mem.second);
                if(loadLoc == storeLoc) {
                    address_t address;
                    std::tie(found, address) = parseBaseAddress(ss, mem.first);
                    if(found) {
                        addr = address;
                        return true;
                    }
                }
            }
        }
        return false;
    };
    FlowUtil::searchUpDef<LoadForm>(state, reg, parser);
    return std::make_tuple(found, addr);
}

auto JumptableDetection::parseMovedAddress(UDState *state, int reg)
    -> std::tuple<bool, address_t> {

#ifdef ARCH_X86_64
    typedef TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>
    > MoveForm;

    address_t addr = 0;
    bool found = false;
    auto parser = [&](UDState *s, TreeCapture& cap) {
        auto regTree = dynamic_cast<TreeNodePhysicalRegister *>(cap.get(0));
        std::tie(found, addr) = parseBaseAddress(s, regTree->getRegister());
        if(found) {
            found = true;
            return true;
        }
        return false;
    };
    FlowUtil::searchUpDef<MoveForm>(state, reg, parser);
    return std::make_tuple(found, addr);
#elif defined(ARCH_AARCH64)
    return std::make_tuple(false, 0);
#elif defined(ARCH_RISCV)
    assert(0); // XXX: no idea
    return std::make_tuple(false, 0);
#endif
}

auto JumptableDetection::parseComputedAddress(UDState *state, int reg)
    -> std::tuple<bool, address_t> {

#ifdef ARCH_X86_64
    return std::make_tuple(false, 0);
#elif defined(ARCH_AARCH64)
    typedef TreePatternBinary<TreeNodeAddition,
        TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>,
        TreePatternCapture<TreePatternTerminal<TreeNodeConstant>>
    > MakeBaseAddressForm;

    address_t addr = 0;
    bool found = false;
    auto parser = [&](UDState *s, TreeCapture& cap) {
        auto regTree = dynamic_cast<TreeNodePhysicalRegister *>(cap.get(0));
        address_t page;
        std::tie(found, page) = parseBaseAddress(s, regTree->getRegister());
        if(found) {
            auto offsetTree = dynamic_cast<TreeNodeConstant *>(cap.get(1));
            addr = page + offsetTree->getValue();
            found = true;
            return true;
        }
        return false;
    };
    FlowUtil::searchUpDef<MakeBaseAddressForm>(state, reg, parser);
    return std::make_tuple(found, addr);
#elif defined(ARCH_RISCV)
    
    assert(0); // XXX: no idea
    return std::make_tuple(false, 0);
#endif
}

void JumptableDetection::collectJumpsTo(UDState *state, JumptableInfo *info,
    std::set<UDState *>& visited, std::vector<UDState *> &result) {

    // Avoid visiting the same node twice in case of cycles
    if(visited.find(state) != visited.end()) return;
    visited.insert(state);

    for(auto &link : state->getNode()->backwardLinks()) {
        LOG(10, "    processing link: " << &link);
        auto prec = info->cfg->get(link->getTargetID());
        auto last = info->working->getState(
            prec->getBlock()->getChildren()->getIterable()->getLast());
        if(dynamic_cast<ControlFlowInstruction *>(last->getInstruction()->getSemantic())) {
            result.push_back(last);
        }
        else {
            collectJumpsTo(last, info, visited, result);
        }
    }
}

bool JumptableDetection::parseBound(UDState *state, int reg,
    JumptableInfo *info) {

#ifdef ARCH_X86_64
    typedef TreePatternBinary<TreeNodeComparison,
        TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>,
        TreePatternCapture<TreePatternTerminal<TreeNodeConstant>>
    > ComparisonForm;

    bool found = false;
    std::map<UDState *, int> list;
    auto parser = [&, info](UDState *s, int r, TreeCapture& cap) {
        LOG(11, "parser considering register " << r);
        if(r == X86Register::FLAGS) { // cmp + jump
            IF_LOG(10) {
                LOG(11, "parser s = " << std::hex << s->getInstruction()->getAddress());
                s->dumpState();
            }
            auto boundTree = dynamic_cast<TreeNodeConstant *>(cap.get(1));
            if(getBoundFromCompare(s, boundTree->getValue(), info)) {
                // this check here is too strict and rejects a known jump
                // table bound in gcc (add_location_or_const_attribute),
                // but that can be found later by other passes
                std::set<UDState *> visited;
                std::vector<UDState *> precList;
                collectJumpsTo(info->jumpState, info, visited, precList);
                for(auto jump : precList) {
                    long bound = info->entries;
                    if(valueReaches(
                        s, X86Register::FLAGS, jump, X86Register::FLAGS, &bound)) {

                        LOG(10, " FLAGS reaches" << std::hex
                            << " from " << s->getInstruction()->getAddress()
                            << " to " << state->getInstruction()->getAddress());
                        LOG(10, "FLAGS 0x"
                            << std::hex << s->getInstruction()->getAddress());
                        if(bound != info->entries) {
                            LOG(10, "bound changed during valueReaches");
                        }
                        info->entries = bound;
                        list[s] = info->entries;
                        found = true;
                        return true;
                    }
                }
                LOG(10, "    condition flags" << std::hex
                    << " set at " << s->getInstruction()->getAddress()
                    << " doesn't reach " << state->getInstruction()->getAddress());
            }
        }
        return false;
    };

    LOG(10, "parseBound 0x"
        << std::hex << state->getInstruction()->getAddress()
        << " reg " << std::dec << reg);
    IF_LOG(10) state->dumpState();
    for(auto s : state->getRegRef(reg)) {
        if(s == state) continue;
        IF_LOG(10) {
            LOG(10, "s : state->getRegRef");
            s->dumpState();
        }
        FlowUtil::searchDownUse<ComparisonForm>(s, reg, parser);
        LOG(15, "    search in state " << s << " yields " << list.size());

        if(!list.empty()) {
            auto prune = [&](int id, int src, int dest) {
                return id == state->getNode()->getID();
            };
            while (list.size() > 1) {
                auto sz = list.size();
                auto it = list.begin();
                for(const auto &pair : list) {
                    if(it->first == pair.first) continue;

                    if(isReachable(info->cfg,
                        it->first->getNode()->getID(),
                        pair.first->getNode()->getID(),
                        prune)) {

                        list.erase(it);
                        break;
                    }
                }
                if(sz == list.size()) {
                    info->cfg->dumpDot();
                    for(auto pair : list) {
                        LOG(1, " " << std::hex
                            << pair.first->getInstruction()->getAddress());
                        pair.first->dumpState();
                    }
                    std::cout.flush();
                    assert(sz > list.size());
                }
            }
            info->entries = list.begin()->second;
            LOG(10, "entries = " << info->entries);
            break;
        }

#if 0
        IF_LOG(10)
            for(auto &s2 : s->getRegUse(reg)) {
                s2->dumpState();
            }
#endif
    }

    if(!found) {
        for(auto s : state->getRegRef(reg)) {
            if(s != state &&
                s->getInstruction()->getParent() ==
                    state->getInstruction()->getParent()) {

                if(getBoundFromSub(s, reg, info)) {
                    found = true;
                    break;
                }

                if(getBoundFromAnd(s, reg, info)) {
                    found = true;
                    break;
                }

                if(getBoundFromMove(s, reg, info)) {
                    found = true;
                    break;
                }
                if(getBoundFromIndexTable(s, reg, info)) {
                    found = true;
                    break;
                }
            }
        }
    }
    if(!found) {
        bool defined = false;
        for(auto s : state->getRegRef(reg)) {
            if(s->getRegDef(reg)) {
                defined = true;
                break;
            }
        }
        if(!defined && getBoundFromArgument(state, reg, info)) {
            found = true;
        }
    }
    if(!found) {
        if(getBoundFromLoad(state, reg, info)) {
            found = true;
        }
    }
#if 0
    // gets confused for binaries generated by clang
    if(!found) {
        if(getBoundFromBitTest(state, reg, info)) {
            found = true;
        }
    }
#endif
    if(!found) {
        for(auto s : state->getRegRef(reg)) {
            if(getBoundFromMove(s, reg, info)) {
                found = true;
                break;
            }

#if 0
            // gets confused for binaries generated by clang
            if(getBoundFromAnd(s, reg, info)) {
                found = true;
                break;
            }
#endif
        }
    }
    if(!found) {
        if(getBoundFromControlFlow(state, reg, info)) {
            found = true;
        }
    }
    if(found) {
        LOG(10, "entries = " << std::dec << info->entries);
    }
    else {
        LOG(10, "no condition?");
    }
    LOG(10, "======");

    LOG(10, "bound found? " << (found ? "yes" : "no") << " entries: " << std::dec << info->entries << std::hex);

    return found;
#elif defined(ARCH_AARCH64)
    typedef TreePatternBinary<TreeNodeComparison,
        TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>,
        TreePatternCapture<TreePatternTerminal<TreeNodeConstant>>
    > ComparisonForm;

    bool found = false;
    auto parser = [&, info](UDState *s, int reg, TreeCapture& cap) {
        if(reg == AARCH64GPRegister::NZCV) { // cmp
            auto boundTree = dynamic_cast<TreeNodeConstant *>(cap.get(1));
            if(getBoundFromCompare(s, boundTree->getValue(), info)) {
                LOG(10, "NZCV 0x"
                    << std::hex << s->getInstruction()->getAddress());
                found = true;
            }
        }
        if(reg == AARCH64GPRegister::ONETIME_NZCV) { // cbz, cbnz
            auto regTree = dynamic_cast<TreeNodePhysicalRegister *>(cap.get(0));
            if(getBoundFromCompareAndBranch(s, regTree->getRegister(),
                info)) {

                LOG(10, "ONETIME NZCV: 0x"
                    << std::hex << s->getInstruction()->getAddress());
                found = true;
            }
        }
        return found;
    };

    LOG(10, "parseBound 0x"
        << std::hex << state->getInstruction()->getAddress()
        << " reg " << std::dec << reg);
    IF_LOG(10) state->dumpState();

    // search up where reg is defined and look downward
    for(auto s : state->getRegRef(reg)) {
        // first check if there is any use (other than this)
        FlowUtil::searchDownUse<ComparisonForm>(s, reg, parser);
        if(found) break;

        // if not
        if(getBoundFromMove(s, reg, info)) {
            found = true;
            break;
        }
        if(getBoundFromIndexTable(s, reg, info)) {
            found = true;
            break;
        }
    }

    // more expensive in general
    if(!found) {
        bool defined = false;
        for(auto s : state->getRegRef(reg)) {
            // BL would just define it as nullptr
            if(s->getRegDef(reg)) {
                defined = true;
                break;
            }
        }
        if(!defined && getBoundFromArgument(state, reg, info)) {
            found = true;
        }
    }
    if(found) {
        LOG(10, "entries = " << std::dec << info->entries);
    }
    if(!found) {
        LOG(10, "no condition?");
    }
    LOG(10, "======");
    return found;
#elif defined(ARCH_RISCV)
    // XXX: no idea
    assert(0);
    return false;
#endif
}

bool JumptableDetection::parseBoundDeref(UDState *state, TreeNodeDereference *deref,
    int reg, JumptableInfo *info) {

    int reg0 = dynamic_cast<TreeNodePhysicalRegister *>(deref->getChild())->getRegister();

    LOG(11, "parseBoundDeref! reg=" << reg << ", reg0=" << reg0);

#ifdef ARCH_X86_64
    typedef TreePatternBinary<TreeNodeComparison,
        TreePatternCapture<TreePatternAny>,
        TreePatternCapture<TreePatternTerminal<TreeNodeConstant>>
    > ComparisonDerefForm;

    bool found = false;
    std::map<UDState *, int> list;
    auto parser = [&, info](UDState *s, int r, TreeCapture& cap) {
        if(r != X86Register::FLAGS) return false;

        LOG(11, "        parser sees match in " << s << ", instr="
            << s->getInstruction()->getName());

        if(/*auto regTree = */dynamic_cast<TreeNodePhysicalRegister *>(cap.get(0))) {
            // continue
        }
        else if(/*auto derefTree = */dynamic_cast<TreeNodeDereference *>(cap.get(0))) {
            if(reg0 != dynamic_cast<TreeNodePhysicalRegister *>(deref->getChild())->getRegister()) {
                return false;
            }
        }
        else return false;

#if 1
        IF_LOG(10) {
            LOG(1, "parser s = " << std::hex << s->getInstruction()->getAddress());
            s->dumpState();
        }
        auto boundTree = dynamic_cast<TreeNodeConstant *>(cap.get(1));
        if(getBoundFromCompare(s, boundTree->getValue(), info)) {
            // this check here is too strict and rejects a known jump
            // table bound in gcc (add_location_or_const_attribute),
            // but that can be found later by other passes
            std::set<UDState *> visited;
            std::vector<UDState *> precList;
            collectJumpsTo(info->jumpState, info, visited, precList);
            for(auto jump : precList) {
                long bound = info->entries;
                if(valueReaches(
                    s, X86Register::FLAGS, jump, X86Register::FLAGS, &bound)) {

                    LOG(10, " FLAGS reaches" << std::hex
                        << " from " << s->getInstruction()->getAddress()
                        << " to " << state->getInstruction()->getAddress());
                    LOG(10, "FLAGS 0x"
                        << std::hex << s->getInstruction()->getAddress());
                    if(bound != info->entries) {
                        LOG(10, "bound changed during valueReaches");
                    }
                    info->entries = bound;
                    list[s] = info->entries;
                    found = true;
                    return true;
                }
            }
            LOG(10, "    condition flags" << std::hex
                << " set at " << s->getInstruction()->getAddress()
                << " doesn't reach " << state->getInstruction()->getAddress());
        }
#endif
        return false;
    };

    LOG(10, "parseBoundDeref 0x"
        << std::hex << state->getInstruction()->getAddress()
        << " reg " << std::dec << reg);
    IF_LOG(10) state->dumpState();
    for(auto s0 : state->getRegRef(reg)) {
        LOG(11, "  state " << s0->getInstruction()->getName() << " references " << reg);
        for(auto s : s0->getRegRef(reg0)) {
            LOG(11, "    state " << s->getInstruction()->getName() << " references " << reg0);
            if(s == state) continue;
            /*IF_LOG(10) {
                LOG(1, "s : state->getRegRef");
                s->dumpState();
            }*/
            FlowUtil::searchDownUse<ComparisonDerefForm>(s, reg0, parser);
            //FlowUtil::searchUpDef<ComparisonDerefForm>(s, reg, parser);
            LOG(15, "    search in state " << s->getInstruction()->getName() << " yields " << list.size());

            if(!list.empty()) {
                auto prune = [&](int id, int src, int dest) {
                    return id == state->getNode()->getID();
                };
                while (list.size() > 1) {
                    auto sz = list.size();
                    auto it = list.begin();
                    for(const auto &pair : list) {
                        if(it->first == pair.first) continue;

                        LOG(1, "checking " << std::hex
                            << pair.first->getInstruction()->getAddress());
                        if(isReachable(info->cfg,
                            it->first->getNode()->getID(),
                            pair.first->getNode()->getID(),
                            prune)) {

                            LOG(1, "deleting from list " << std::hex
                                << it->first->getInstruction()->getAddress());
                            list.erase(it);
                            break;
                        }
                    }
                    if(sz == list.size()) {
                        info->cfg->dumpDot();
                        LOG(1, "multiple bound?");
                        for(auto pair : list) {
                            LOG(1, " " << std::hex
                                << pair.first->getInstruction()->getAddress());
                            pair.first->dumpState();
                        }
                        std::cout.flush();
                        assert(sz > list.size());
                    }
                }
                info->entries = list.begin()->second;
                LOG(10, "entries = " << info->entries);
                break;
            }
        }
    }

    if(found) {
        LOG(10, "entries = " << std::dec << info->entries);
    }
    else {
        LOG(10, "no condition?");
    }
    LOG(10, "======");

    return found;
#else
    return false;
#endif
}

#ifdef ARCH_X86_64
static bool isReachableIfTaken(ControlFlowGraph *cfg, UDState *s, int to) {
    for(auto& link : s->getNode()->forwardLinks()) {
        if(link->getTargetID() == s->getNode()->getID() + 1) continue;
        if(isReachable<Preorder>(cfg, link->getTargetID(), to)) {
            return true;
        }
    }
    return false;
}
static bool isReachableIfNotTaken(ControlFlowGraph *cfg, UDState *s, int to) {
    if(isReachable<Preorder>(cfg, s->getNode()->getID() + 1, to)) {
        return true;
    }
    return false;
}
#endif

bool JumptableDetection::getBoundFromCompare(UDState *state, int bound,
    JumptableInfo *info) {

#ifdef ARCH_X86_64
    std::vector<UDState *> branches;

    LOG(10, "getBoundFromCompare " << std::dec << bound);
    auto jumpNodeID = info->jumpState->getNode()->getID();
    for(auto s : state->getRegUse(X86Register::FLAGS)) {
        LOG(10, "s = 0x" << std::hex << s->getInstruction()->getAddress());
        IF_LOG(10) s->dumpState();
        if(isReachable<Preorder>(
            info->cfg, state->getNode()->getID(), jumpNodeID)) {

            LOG(10, "this is reachable");
            branches.push_back(s);
        }
    }

    LOG(10, std::dec << branches.size() << " branches");
    for(auto s : branches) {
        auto semantic = s->getInstruction()->getSemantic();
        auto cfi = dynamic_cast<ControlFlowInstruction *>(semantic);
        if(!cfi) continue;

        auto mnemonic = cfi->getMnemonic();
        LOG(10, "branch " << mnemonic << " at " << std::hex << s->getInstruction()->getAddress());
        if(mnemonic == "jne") continue;
        if(mnemonic == "je") continue;
        if(mnemonic == "jle") {
            LOG(10, "should be lower or same (<=)");
            if(isReachableIfTaken(info->cfg, s, jumpNodeID)) {
                info->entries = bound + 1;
                return true;
            }
        }
        else if(mnemonic == "jb") {
            LOG(10, "should be lower (<)");
            if(isReachableIfTaken(info->cfg, s, jumpNodeID)) {
                info->entries = bound;
                return true;
            }
        }
        else if(mnemonic == "ja") {
            LOG(10, "should (NOT) be higher (!>)");
            if(isReachableIfNotTaken(info->cfg, s, jumpNodeID)) {
                info->entries = bound + 1;
                return true;
            }
        }
        else if(mnemonic == "jae") {
            LOG(10, "should (NOT) be higher or same (!>=)");
            if(isReachableIfNotTaken(info->cfg, s, jumpNodeID)) {
                info->entries = bound;
                return true;
            }
        }
        else {
            LOG(10, "unknown corresponding branch at 0x" << std::hex
                << s->getInstruction()->getAddress() << " " << mnemonic);
        }
    }
    return false;
#elif defined(ARCH_AARCH64)
    std::vector<UDState *> branches;

    auto jumpNodeID = info->jumpState->getNode()->getID();
    for(auto s : state->getRegUse(AARCH64GPRegister::NZCV)) {
        LOG(10, "s = 0x" << s->getInstruction()->getAddress());
        IF_LOG(10) s->dumpState();

        for(auto link : s->getNode()->forwardLinks()) {
            if(link->getTargetID() == jumpNodeID) {
                branches.push_back(s);
            }
        }
    }

    for(auto s : branches) {
        auto assembly = s->getInstruction()->getSemantic()->getAssembly();
        if(assembly->getMnemonic() == "b.ne") continue;
        if(assembly->getMnemonic() == "b.eq") continue;
        if(assembly->getMnemonic() == "b.ls") {
            LOG(10, "should be lower or same (<=)");
            info->entries = bound + 1;
            return true;
        }
        else if(assembly->getMnemonic() == "b.hi") {
            LOG(10, "should (NOT) be higher (!>)");
            info->entries = bound + 1;
            return true;
        }
        else {
            LOG(10, "unknown corresponding branch at 0x" << std::hex
                << s->getInstruction()->getAddress()
                << " " << assembly->getMnemonic());
        }
    }
    return false;
#elif defined(ARCH_RISCV)
    assert(0); // XXX: no idea
    return false;
#endif
}

bool JumptableDetection::getBoundFromCompareAndBranch(UDState *state, int reg,
    JumptableInfo *info) {

    auto jumpNodeID = info->jumpState->getNode()->getID();

    for(auto link : state->getNode()->forwardLinks()) {
        if(link->getTargetID() == jumpNodeID) {
            LOG(1, "NYI: condition register is " << reg);
            break;
        }
    }
    return false;
}

bool JumptableDetection::getBoundFromSub(UDState *state, int reg,
    JumptableInfo *info) {

    typedef TreePatternBinary<TreeNodeSubtraction,
        TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>,
        TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>
    > SubtractionForm;

    LOG(10, "getBoundFromSub 0x"
        << std::hex << state->getInstruction()->getAddress()
        << " reg " << std::dec << reg);
    IF_LOG(10) state->dumpState();

    auto def = state->getRegDef(reg);
    TreeCapture capture;
    if(SubtractionForm::matches(def, capture)) {
        auto regTree0
            = dynamic_cast<TreeNodePhysicalRegister *>(capture.get(0));
        auto regTree1
            = dynamic_cast<TreeNodePhysicalRegister *>(capture.get(1));
        assert(regTree0->getRegister() == reg);

        auto boundReg = regTree1->getRegister();
        for(auto ref : state->getRegRef(boundReg)) {
            if(getBoundFromAnd(ref, boundReg, info)) {
                return true;
            }
        }
    }

    return false;
}

bool JumptableDetection::getBoundFromMove(UDState *state, int reg,
    JumptableInfo *info) {

#ifdef ARCH_X86_64
    typedef TreePatternBinary<TreeNodeComparison,
        TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>,
        TreePatternCapture<TreePatternTerminal<TreeNodeConstant>>
    > ComparisonForm;
#endif

    auto def = state->getRegDef(reg);
    if(auto tree = dynamic_cast<TreeNodePhysicalRegister *>(def)) {
        LOG(10, "MOVE");

#ifdef ARCH_X86_64
        // search downward
        for(auto s : state->getRegUse(reg)) {
            if(auto flagTree = s->getRegDef(X86Register::FLAGS)) {
                TreeCapture capture;
                if(ComparisonForm::matches(flagTree, capture)) {
                    auto regTree0 = dynamic_cast<TreeNodePhysicalRegister *>(
                        capture.get(0));
                    if(regTree0->getRegister() != reg) continue;
                    auto boundTree = dynamic_cast<TreeNodeConstant *>(
                        capture.get(1));
                    if(getBoundFromCompare(s, boundTree->getValue(), info)) {
                        return true;
                    }
                }
            }
        }
#endif

        // search upward
        if(parseBound(state, tree->getRegister(), info)) {
            return true;
        }
    }
    return false;
}

bool JumptableDetection::getBoundFromAnd(UDState *state, int reg,
    JumptableInfo *info) {

    typedef TreePatternBinary<TreeNodeAnd,
        TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>,
        TreePatternCapture<TreePatternTerminal<TreeNodeConstant>>
    > AndForm;

    LOG(10, "getBoundFromAnd 0x"
        << std::hex << state->getInstruction()->getAddress()
        << " reg " << std::dec << reg);
    IF_LOG(10) state->dumpState();

    TreeCapture capture;
    if(AndForm::matches(state->getRegDef(reg), capture)) {
        LOG(10, "AndForm matches");
        IF_LOG(10) state->dumpState();
        auto boundTree = dynamic_cast<TreeNodeConstant *>(capture.get(1));
        info->entries = boundTree->getValue() +1;
        return true;
    }
    return false;
}

#ifdef ARCH_X86_64
bool JumptableDetection::getBoundFromLoad(UDState *state, int reg,
    JumptableInfo *info) {

    typedef TreePatternUnary<TreeNodeDereference,
        TreePatternCapture<TreePatternBinary<TreeNodeAddition,
            TreePatternTerminal<TreeNodePhysicalRegister>,
            TreePatternTerminal<TreeNodeConstant>
        >>
    > MemoryForm;

    typedef TreePatternBinary<TreeNodeComparison,
        TreePatternUnary<TreeNodeDereference,
            TreePatternCapture<TreePatternBinary<TreeNodeAddition,
                TreePatternTerminal<TreeNodePhysicalRegister>,
                TreePatternTerminal<TreeNodeConstant>
            >>
        >,
        TreePatternCapture<TreePatternTerminal<TreeNodeConstant>>
    > ComparisonForm;

    bool found = false;

    std::vector<std::pair<UDState *, MemLocation>> loadStates;
    auto parser1 = [&, info](UDState *s, TreeCapture& cap) {
        LOG(10, "s1 = " << s->getInstruction()->getAddress());
        IF_LOG(10) s->dumpState();
        loadStates.emplace_back(s, cap.get(0));
        return false;   // collect all
    };

    LOG(10, "getBoundFromLoad 0x"
        << std::hex << state->getInstruction()->getAddress()
        << " reg " << std::dec << reg);
    IF_LOG(10) state->dumpState();
    FlowUtil::searchUpDef<MemoryForm>(state, reg, parser1);
    if(loadStates.empty()) return false;

    for(const auto& pair : loadStates) {
        auto s = pair.first;
        auto& memLocation = pair.second;
        auto r = dynamic_cast<TreeNodePhysicalRegister *>(
            memLocation.getRegTree())->getRegister();
        LOG(10, "  r = " << std::dec << r);
        for(auto& s2 : s->getRegRef(r)) {
            LOG(10, "  s2 = " << std::hex << s->getInstruction()->getAddress());
            IF_LOG(10) s2->dumpState();
            LOG(10, "should look at use states in 0x"
                << std::hex << s2->getInstruction()->getAddress());
            for(auto& s3 : s2->getRegUse(r)) {
                TreeCapture capture;
                LOG(10, "s3 = " << std::hex
                    << s3->getInstruction()->getAddress());
                if(auto def = s3->getRegDef(X86Register::FLAGS)) {
                    LOG(10, "flags defined in "
                        << std::hex << s3->getInstruction()->getAddress());
                    IF_LOG(10) s3->dumpState();
                    if(ComparisonForm::matches(def, capture)) {
                        if(memLocation != MemLocation(capture.get(0))) continue;
                        auto boundTree
                            = dynamic_cast<TreeNodeConstant *>(capture.get(1));
                        if(getBoundFromCompare(s3, boundTree->getValue(),
                            info)) {

                            LOG(10, "found!");
                            found = true;
                        }
                    }
                }
            }
        }
    }

    typedef TreePatternBinary<TreeNodeComparison,
        TreePatternTerminal<TreeNodePhysicalRegister>,
        TreePatternCapture<TreePatternTerminal<TreeNodeConstant>>
    > ComparisonForm2;

    if(!found) {
        LOG(10, "checking if there was store to this location");
        for(const auto& pair : loadStates) {
            for(auto& ref : pair.first->getMemRef(reg)) {
                for(auto& m : ref->getMemDefList()) {
                    if(pair.second == MemLocation(m.second)) {
                        for(auto& def : ref->getRegRef(m.first)) {
                            for(auto& use : def->getRegUse(m.first)) {
                                auto flagTree
                                    = use->getRegDef(X86Register::FLAGS);
                                TreeCapture capture;
                                if(ComparisonForm2::matches(
                                    flagTree, capture)) {

                                    LOG(10, "comparison in " << std::hex
                                        << use->getInstruction()->getAddress());
                                    auto boundTree = dynamic_cast<
                                        TreeNodeConstant *>(capture.get(0));
                                    if(getBoundFromCompare(use,
                                        boundTree->getValue(),
                                        info)) {

                                        found = true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    auto parser2 = [&, info](UDState *s, TreeCapture& cap) {
        LOG(10, "s = 0x" << std::hex << s->getInstruction()->getAddress());
        IF_LOG(10) s->dumpState();
        for(auto& pair : loadStates) {
            if(pair.second == MemLocation(cap.get(0))) {
                auto boundTree = dynamic_cast<TreeNodeConstant *>(cap.get(1));
                if(getBoundFromCompare(s, boundTree->getValue(), info)) {
                    LOG(10, "FOUND!");
                    found = true;
                    return true;
                }
            }
        }
        return false;
    };
    if(!found) {
        LOG(10, "checking against an argument on stack");
        ReverseReversePostorder order(info->cfg);
        for(const auto& pair : loadStates) {
            auto s = pair.first;
            order.gen(s->getNode()->getID());
            auto vec = order.get()[0];
            for(auto it = vec.begin() + 1; it != vec.end(); ++it) {
                auto block = info->cfg->get(*it)->getBlock();
                auto instr = block->getChildren()->getIterable()->getLast();
                auto s = info->working->getState(instr);
                FlowUtil::searchUpDef<ComparisonForm>(
                    s, X86Register::FLAGS, parser2);
                if(found) {
                    return true;
                }
            }
        }
    }
    return found;
}
#endif

#if 0
bool JumptableDetection::getBoundFromBitTest(UDState *state, int reg,
    JumptableInfo *info) {

    LOG(10, "getBoundFromBitTest 0x"
        << std::hex << state->getInstruction()->getAddress()
        << " reg " << std::dec << reg);
    IF_LOG(10) state->dumpState();

#ifdef ARCH_X86_64
    typedef TreePatternBinary<TreeNodeAnd,
        TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>,
        TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>
    > BitTestForm;

    // the register should be the same, otherwise it must have a def tree
    bool found = false;
    auto parser = [&, info](UDState *s, TreeCapture& cap) {
        LOG(10, "s = 0x" << std::hex << s->getInstruction()->getAddress());
        IF_LOG(10) s->dumpState();
        TreeNodePhysicalRegister *regTree = nullptr;
        TreeNodePhysicalRegister *otherTree = nullptr;
        regTree = dynamic_cast<TreeNodePhysicalRegister *>(cap.get(0));
        otherTree = dynamic_cast<TreeNodePhysicalRegister *>(cap.get(1));
        if(otherTree->getRegister() == reg) {
            auto tmp = regTree;
            regTree = otherTree;
            otherTree = tmp;
        }
        if(regTree->getRegister() != reg) return false;
        LOG(10, "   should look for R" << std::dec << otherTree->getRegister());
        for(auto& s2 : s->getRegRef(otherTree->getRegister())) {
            LOG(10, "    s2 = 0x"
                << std::hex << s2->getInstruction()->getAddress());
            IF_LOG(10) s2->dumpState();
            if(auto bitTree = dynamic_cast<TreeNodeConstant *>(
                s2->getRegDef(otherTree->getRegister()))) {

                auto bits = bitTree->getValue();
                int pos = 0;
                while(bits) {
                    bits>>=1;
                    pos++;
                }
                if(getBoundFromCompare(s, pos, info)) {
                    found = true;
                    return true;
                }
            }
        }
        return false;
    };

    LOG(10, "finding bit test against " << std::dec << reg);

    ReverseReversePostorder order(info->cfg);
    order.gen(info->jumpState->getNode()->getID());
    auto vec = order.get()[0];
    for(auto it = vec.begin() + 1; it != vec.end(); ++it) {
        LOG(10, "checking " << *it);
        auto block = info->cfg->get(*it)->getBlock();
        auto instr = block->getChildren()->getIterable()->getLast();
        auto s = info->working->getState(instr);
        FlowUtil::searchUpDef<BitTestForm>(s, X86Register::FLAGS, parser);
        if(found) {
            return true;
        }
    }
#endif
    return false;
}
#endif

// for manually crafted jumptables in C
bool JumptableDetection::getBoundFromIndexTable(UDState *state, int reg,
    JumptableInfo *info) {

#ifdef ARCH_X86_64
    typedef TreePatternCapture<TreePatternUnary<TreeNodeDereference,
        TreePatternBinary<TreeNodeAddition,
            TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>,
            TreePatternBinary<TreeNodeMultiplication,
                TreePatternCapture<
                    TreePatternTerminal<TreeNodePhysicalRegister>>,
                TreePatternCapture<TreePatternTerminal<TreeNodeConstant>>
            >
        >
    >> IndexTableAccessForm;

    typedef TreePatternBinary<TreeNodeComparison,
        TreePatternUnary<TreeNodeDereference,
            TreePatternCapture<TreePatternBinary<TreeNodeAddition,
                TreePatternTerminal<TreeNodePhysicalRegister>,
                TreePatternBinary<TreeNodeMultiplication,
                    TreePatternTerminal<TreeNodePhysicalRegister>,
                    TreePatternCapture<TreePatternTerminal<TreeNodeConstant>>
                >
            >>
        >,
        TreePatternCapture<TreePatternTerminal<TreeNodeConstant>>
    > ComparisonForm2;

    TreeCapture capture;
    if(IndexTableAccessForm::matches(state->getRegDef(reg), capture)) {
        auto derefTree
            = dynamic_cast<TreeNodeDereference *>(capture.get(0));
        auto regTree1
            = dynamic_cast<TreeNodePhysicalRegister *>(capture.get(1));
        auto regTree2
            = dynamic_cast<TreeNodePhysicalRegister *>(capture.get(2));
        auto scaleTree = dynamic_cast<TreeNodeConstant *>(capture.get(3));

        LOG(10, "Dereference from index table at " << std::hex
            << state->getInstruction()->getAddress());
        IF_LOG(10) state->dumpState();

        bool found = false;

        // if there is a direct comparison of the MemLocation in the
        // immediate preceding nodes, then the bound obtained is actually
        // the bounds of the jump table
        MemLocation m(derefTree->getChild());
        auto parser = [&, info](UDState *s, int r, TreeCapture& cap) {
            if(r == X86Register::FLAGS) { // cmp + jump
                if(m != MemLocation(cap.get(0))) {
                    LOG(10, " mem locations don't match");
                    return false;
                }

                IF_LOG(10) {
                    LOG(10, "matched ComparisonForm2 = " << std::hex
                        << s->getInstruction()->getAddress());
                    s->dumpState();
                }
                auto boundTree = dynamic_cast<TreeNodeConstant *>(cap.get(2));
                if(getBoundFromCompare(s, boundTree->getValue(), info)) {
                    LOG(10, "found DIRECT comparison");
                    found = true;
                    return true;
                }
            }
            return false;
        };
        for(auto s : state->getRegRef(reg)) {
            FlowUtil::searchDownUse<ComparisonForm2>(
                s, regTree2->getRegister(), parser);
            if(found) {
                return true;
            }
        }

        address_t indexTableBase = 0;
        size_t indexTableScale = 0;
        size_t indexTableEntries = 0;

        std::tie(found, indexTableBase)
            = parseBaseAddress(state, regTree1->getRegister());
        if(found) {
            auto it = indexTables.find(indexTableBase);
            if(it != indexTables.end()) {
                LOG(10, "index table for this base is already known");
                indexTableScale = it->second.scale;
                indexTableEntries = it->second.entries;
            }
            else {
                JumptableInfo indexInfo = *info;
                indexInfo.jumpState = state;   // !!! this isn't jump

                indexTableScale = scaleTree->getValue();

                parseBound(state, regTree2->getRegister(), &indexInfo);
                indexTableEntries = indexInfo.entries;

                LOG(10, "index table found! at 0x"
                    << std::hex << indexTableBase << " with "
                    << std::dec << indexTableEntries << " entries of size "
                    << std::dec << indexTableScale << " each");

                if(indexTableEntries > 0) {
                    indexTables.emplace(std::piecewise_construct,
                        std::forward_as_tuple(indexTableBase),
                        std::forward_as_tuple(indexTableScale,
                            indexTableEntries));
                }
            }
            if(indexTableEntries > 0) {
                auto elfMap = module->getElfSpace()->getElfMap();
                auto copyBase = elfMap->getCopyBaseAddress();
                address_t mapEnd = reinterpret_cast<address_t>(
                    elfMap->getCharmap() + elfMap->getLength());
                if(mapEnd < copyBase + indexTableBase) {
                    // the index table is dynamically filled!
                    // hopefully JumpTableBounds will find it
                    return false;
                }
                size_t max = 0;
                if(indexTableScale == 1) {
                    for(size_t i = 0; i < indexTableEntries; i++) {
                        max = std::max(max, static_cast<size_t>(
                            *(char *)(copyBase + indexTableBase + i)));
                    }
                }
                else if(indexTableScale == 4) {
                    for(size_t i = 0; i < indexTableEntries; i++) {
                        max = std::max(max, static_cast<size_t>(
                            *(uint32_t *)(copyBase + indexTableBase + i*4)));
                    }
                }
                else {
                    assert(indexTableScale == 1 || indexTableBase == 4);
                }
                LOG(10, "max = " << std::dec << max);
                info->entries = max + 1;
                return true;
            }
        }
    }
    return false;
#elif defined(ARCH_AARCH64)
    typedef TreePatternUnary<TreeNodeDereference,
        TreePatternBinary<TreeNodeAddition,
            TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>,
            TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>
        >
    > IndexTableAccessForm;

    typedef TreePatternBinary<TreeNodeAddition,
        TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>,
        TreePatternCapture<TreePatternTerminal<TreeNodeConstant>>
    > MakeTableIndexForm;

    TreeCapture capture;
    if(IndexTableAccessForm::matches(state->getRegDef(reg), capture)) {
        LOG(10, "Dereference from index table at " << std::hex
            << state->getInstruction()->getAddress());
        bool found = false;

        auto parser = [&, info](UDState *s, TreeCapture& cap) {
            auto boundTree = dynamic_cast<TreeNodeConstant *>(cap.get(1));
            info->entries = boundTree->getValue() / info->scale;
            found = true;
            return true;
        };

        auto baseRegTree
            = dynamic_cast<TreeNodePhysicalRegister *>(capture.get(0));
        LOG(10, "look for reg " << baseRegTree->getRegister());
        FlowUtil::searchUpDef<MakeTableIndexForm>(
            state, baseRegTree->getRegister(), parser);
        return found;
    }
    return false;
#elif defined(ARCH_RISCV)
    assert(0); // XXX: no idea
    return false;
#endif
}

bool JumptableDetection::getBoundFromArgument(UDState *state, int reg,
    JumptableInfo *info) {

#ifdef ARCH_X86_64
    typedef TreePatternBinary<TreeNodeComparison,
        TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>,
        TreePatternCapture<TreePatternTerminal<TreeNodeConstant>>
    > ComparisonForm;

    LOG(10, "getBoundFromArgument 0x"
        << std::hex << state->getInstruction()->getAddress()
        << " reg " << std::dec << reg);
    IF_LOG(10) state->dumpState();

    auto prunePred = [&, info, reg](int n, int src, int dest) {
        auto block = info->cfg->get(n)->getBlock();
        for(auto instr : CIter::children(block)) {
            auto s = info->working->getState(instr);
            if(!s->getRegDef(reg)) continue;
            if(s->getRegRef(reg).empty()) {
                // overwrite [constant or address (RIP-relative lea)]
                LOG(10, "pruned in " << std::hex
                    << s->getInstruction()->getAddress());
                return true;
            }
            // register case is difficult: the following case does not
            // overwrite reg A value
            //   reg A -> reg B
            //   reg B -> reg A
        }
        return false;
    };

    bool found = false;
    auto parser = [&, info](UDState *s, TreeCapture& cap) {
        LOG(10, "s = " << std::hex << s->getInstruction()->getAddress());
        IF_LOG(10) s->dumpState();
        if(!state->getRegRef(reg).empty()) {
            bool reachable = false;
            LOG(10, "    reg has a def node");
            for(auto &ref : state->getRegRef(reg)) {
                reachable = isReachable<Preorder>(info->cfg,
                    ref->getNode()->getID(), s->getNode()->getID());
                if(!reachable && !ref->getRegRef(reg).empty()) {
                    for(auto s2 : ref->getRegRef(reg)) {
                        LOG(10, "  from " << std::hex
                            << s2->getInstruction()->getAddress());
                        reachable = isReachable<Preorder>(info->cfg,
                            s2->getNode()->getID(), s->getNode()->getID());
                        if(reachable) {
                            LOG(10, "reachable from " << std::dec
                                << s2->getNode()->getID() << " to "
                                << s->getNode()->getID());
                            break;
                        }
                    }
                }
                if(!reachable) continue;

                auto reachable2 = false;
                auto stateId = state->getNode()->getID();
                for(auto& link : s->getNode()->forwardLinks()) {
                    auto cflink = dynamic_cast<ControlFlowLink *>(&*link);
                    reachable2 = isReachable(info->cfg,
                        cflink->getTargetID(), stateId, prunePred);
                    if(reachable2) break;
                }

                LOG(10, "   pruned check? " << reachable2
                    << " from " << std::dec
                    << s->getNode()->getID() << " to "
                    << info->jumpState->getNode()->getID());
                if(reachable && !reachable2) {
                    LOG(10, "Oops");
                    reachable = false;
                }
                if(reachable) break;
            }
            if(!reachable) return false;
        }
        auto regTree = dynamic_cast<TreeNodePhysicalRegister *>(cap.get(0));
        if(regTree->getRegister() != reg) return false;
        LOG(10, "   modifies eflags");
        auto boundTree = dynamic_cast<TreeNodeConstant *>(cap.get(1));
        if(getBoundFromCompare(s, boundTree->getValue(), info)) {
            found = true;
            return true;
        }
        return false;
    };

    ReverseReversePostorder order(info->cfg);
    order.gen(info->jumpState->getNode()->getID());
    auto vec = order.get()[0];
    for(auto it = vec.begin() + 1; it != vec.end(); ++it) {
        LOG(10, "checking " << std::dec << *it);
        auto block = info->cfg->get(*it)->getBlock();
        auto instr = block->getChildren()->getIterable()->getLast();
        auto s = info->working->getState(instr);
        FlowUtil::searchUpDef<ComparisonForm>(s, X86Register::FLAGS, parser);
        if(found) {
            return true;
        }
    }
    return false;
#elif defined(ARCH_AARCH64)
    typedef TreePatternBinary<TreeNodeComparison,
        TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>,
        TreePatternCapture<TreePatternTerminal<TreeNodeConstant>>
    > ComparisonForm;

    // the register should be the same, otherwise it must have a def tree
    bool found = false;
    auto parser = [&, info](UDState *s, TreeCapture& cap) {
        auto regTree = dynamic_cast<TreeNodePhysicalRegister *>(cap.get(0));
        if(regTree->getRegister() != reg) return false;
        auto boundTree = dynamic_cast<TreeNodeConstant *>(cap.get(1));
        if(getBoundFromCompare(s, boundTree->getValue(), info)) {
            found = true;
            return true;
        }
        return false;
    };

    ReverseReversePostorder order(info->cfg);
    order.gen(info->jumpState->getNode()->getID());
    auto vec = order.get()[0];
    for(auto it = vec.begin() + 1; it != vec.end(); ++it) {
        LOG(10, "checking " << *it);
        auto block = info->cfg->get(*it)->getBlock();
        auto instr = block->getChildren()->getIterable()->getLast();
        auto s = info->working->getState(instr);
        FlowUtil::searchUpDef<ComparisonForm>(
            s, AARCH64GPRegister::NZCV, parser);    // ONETIME_NZCV is NYI
        if(found) {
            return true;
        }
    }
    return false;
#elif defined(ARCH_RISCV)
    assert(0); // XXX: no idea
    return false;
#endif
}

#ifdef ARCH_X86_64
// handles the case where the index is copied to another register and test
// is performed on that register
bool JumptableDetection::getBoundFromControlFlow(UDState *state, int reg,
    JumptableInfo *info) {

    typedef TreePatternBinary<TreeNodeComparison,
        TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>,
        TreePatternCapture<TreePatternTerminal<TreeNodeConstant>>
    > ComparisonForm;

    LOG(10, "getBoundFromControlFlow 0x"
        << std::hex << state->getInstruction()->getAddress()
        << " reg " << std::dec << reg);

    auto block = dynamic_cast<Block *>(state->getInstruction()->getParent());
    auto cfg = info->cfg;
    auto node = cfg->get(cfg->getIDFor(block));
    for(auto link : node->backwardLinks()) {
        auto precedingBlock = cfg->get(link->getTargetID())->getBlock();
        auto jmp = precedingBlock->getChildren()->getIterable()->getLast();
        auto jstate = info->working->getState(jmp);
        LOG(10, " reaches from " << std::hex << jmp->getAddress());
        for(auto test : jstate->getRegRef(X86Register::FLAGS)) {
            LOG(10, " condition is tested at "
                << std::hex << test->getInstruction()->getAddress());
            auto flagTree = test->getRegDef(X86Register::FLAGS);
            TreeCapture capture;
            if(ComparisonForm::matches(flagTree, capture)) {
                auto regTree
                    = dynamic_cast<TreeNodePhysicalRegister *>(capture.get(0));
                auto boundTree
                    = dynamic_cast<TreeNodeConstant *>(capture.get(1));
                if(getBoundFromCompare(test, boundTree->getValue(), info)) {
                    LOG(10, "   bound could be " << info->entries);
                    // find the common ancestor and see if that value is
                    // never overloaded (modification is fine; no dereference)
                    auto testReg = regTree->getRegister();
                    long bound = info->entries;
                    bool reaches = valueReaches(test, testReg, state, reg, &bound);
                    if(!reaches) {
                        LOG(10, "   NO this is false!");
                        info->entries = 0;
                    }
                    if(reaches) {
                        if(bound != info->entries) {
                            LOG(10, "bound changed during valueReaches");
                        }
                        info->entries = bound;
                        return true;
                    }
                }
            }
        }
    }

    return false;
}

// doesn't trace into stack
bool cutsRegFlow(TreeNode *tree) {
    if(dynamic_cast<TreeNodeDereference *>(tree)) {
        return true;
    }
    return false;
}

static std::pair<bool, long> valueReachesLoop(UDState *state, int reg,
    UDState *state2, int reg2, std::set<UDState *>& seen, long origValue) {

    LOG(10, "valueReachesLoop: " << std::hex
        << state->getInstruction()->getAddress()
        << " reg " << std::dec << reg
        << " ->? "
        << std::hex << state2->getInstruction()->getAddress()
        << " reg " << std::dec << reg2);
    LOG(20, "from state");
    IF_LOG(20) state->dumpState();
    LOG(20, "to state");
    IF_LOG(20) state2->dumpState();

    if(seen.find(state) != seen.end()) return std::make_pair(false, 0);
    seen.insert(state);

    for(auto use : state->getRegUse(reg)) {
        if(use == state2) {
            LOG(10, "  reaches");
            return std::make_pair(true, origValue);
        }
    }

    /*
    state (reg)
        - use (of reg, def of reg_temp)
    state2 (reg2)
     */
    for(auto use : state->getRegUse(reg)) {
        for(auto& def : use->getRegDefList()) {
            if(!def.second) continue;

            if(cutsRegFlow(def.second)) {
                continue;
            }

            long subValue = origValue;

            if(auto sr = dynamic_cast<TreeNodeLogicalShiftRight *>(def.second)) {
                // get shift value
                auto shift = dynamic_cast<TreeNodeConstant *>(sr->getRight());
                if(!shift) {
                    LOG(10, "Non-constant shift");
                    continue;
                }
                else subValue >>= shift->getValue();
            }
            else if(auto sl = dynamic_cast<TreeNodeLogicalShiftLeft *>(def.second)) {
                // get shift value
                auto shift = dynamic_cast<TreeNodeConstant *>(sl->getRight());
                if(!shift) {
                    LOG(10, "Non-constant shift");
                    continue;
                }
                else subValue <<= shift->getValue();
            }
            else if(dynamic_cast<TreeNodePhysicalRegister *>(def.second)) {
                /* don't have to do anything, the value doesn't change */
            }
            else if(dynamic_cast<TreeNodeRegister *>(def.second)) {
                /* don't have to do anything, the value doesn't change */
            }
            else {
                IF_LOG(10) {
                    LOG(10, "skipping TreeNode as potential flow "
                        "to jump table branch:");
                    TreePrinter tp;
                    def.second->print(tp);
                }
                continue;
            }

            auto rv = valueReachesLoop(use, def.first, state2, reg2, seen, subValue);
            if(rv.first) return rv;
        }
    }

    // this should only be effective when common upstream defines a value
    // and it isn't changed (not checked now)
    for(auto ref : state->getRegRef(reg)) {
        auto rv = valueReachesLoop(ref, reg, state2, reg2, seen, origValue);
        if(rv.first) {
            return rv;
        }
        if(cutsRegFlow(ref->getRegDef(reg))) {
            LOG(10, "stop looking in the upstream " << std::hex
                << ref->getInstruction()->getAddress());
            IF_LOG(10) ref->dumpState();
            break;
        }
    }

    return std::make_pair(false, 0);
}

bool JumptableDetection::valueReaches(UDState *state, int reg,
    UDState *state2, int reg2, long *boundValue) {

    std::set<UDState *> seen;
    auto rv = valueReachesLoop(state, reg, state2, reg2, seen, *boundValue);

    if(rv.first && boundValue) *boundValue = rv.second;
    return rv.first;
}
#endif
