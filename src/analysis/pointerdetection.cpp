#include "pointerdetection.h"
#include "analysis/slicingtree.h"
#include "chunk/concrete.h"
#include "instr/isolated.h"
#include "instr/linked-aarch64.h"

#include "log/log.h"

void PointerDetection::detect() {
    UDConfiguration config(1, &cfg);
    UDRegMemWorkingSet working(function, &cfg);
    UseDef usedef(&config, &working);

    cfg.dump();
    cfg.dumpDot();

    SccOrder order(&cfg);
    order.genFull(0);
    usedef.analyze(order.get());

    LOG(5, "");
    LOG(5, "searching for pointers... (checking soundness)");
    for(auto s : working.getStateList()) {
        LOG(5, "state = 0x" << std::hex << s.getInstruction()->getAddress());

        auto regList = s.getRegDefList();
        for(auto it = regList.cbegin(); it != regList.cend(); ++it) {
            if(it->second) {
                detectPointers(&s, it->second);
            }
        }

        auto memList = s.getMemDefList();
        for(auto it = memList.cbegin(); it != memList.cend(); ++it) {
            if(it->second) {
                detectPointers(&s, it->second);
            }
        }
    }

    LOG(5, "checking completeness");
    for(auto block : CIter::children(function)) {
        for(auto instr : CIter::children(block)) {
            auto semantic = instr->getSemantic();
            if(dynamic_cast<ControlFlowInstruction *>(semantic)) {
                continue;
            }
            if(auto linked = dynamic_cast<LinkedInstruction *>(semantic)) {
                auto link = linked->getLink();
                if(dynamic_cast<NormalLink *>(link)
                    || dynamic_cast<DataOffsetLink *>(link)) {

                    LOG(5, "link at 0x" << std::hex << instr->getAddress());
                    auto it = found.find(instr);
                    if(it == found.end()) {
                        LOG(5, "MISMATCH: not found: 0x"
                            << std::hex << link->getTargetAddress()
                            << " at 0x" << std::hex << instr->getAddress());
                    }
                    found.erase(instr);
                }
            }
        }
    }
    if(found.size() > 0) {
        for(auto f : found) {
            LOG(5, "MISMATCH: (was not found): 0x" << std::hex << f.second
                << " at 0x" << f.first->getAddress());
        }
    }
}

void PointerDetection::detectPointers(UDState *state, TreeNode *tree) {
    TreeCapture cap;
    int reg;
    TreeNodeConstant *offset = nullptr;

    LOG(5, "considering");
    IF_LOG(5) tree->print(TreePrinter(0, 0));
    LOG(5, "");

    bool matched = false;
    if(PointerForm::matches(tree, cap)) {
        LOG(5, "PointerForm");
        if(auto r = dynamic_cast<TreeNodePhysicalRegister *>(cap.get(0))) {
            if(r->getWidth() == 8) {
                reg = r->getRegister();
                if(AARCH64GPRegister::isInteger(reg)) {
                    offset = dynamic_cast<TreeNodeConstant *>(cap.get(1));
                    matched = true;
                }
            }
        }
    }
    else {
        cap.clear();
        if(PointerDerefForm::matches(tree, cap)) {
            LOG(5, "PointerDerefForm");
            if(auto r = dynamic_cast<TreeNodePhysicalRegister *>(cap.get(1))) {
                if(r->getWidth() == 8) {
                    reg = r->getRegister();
                    if(AARCH64GPRegister::isInteger(reg)) {
                        offset = dynamic_cast<TreeNodeConstant *>(cap.get(2));
                        matched = true;
                    }
                }
            }
        }
    }
    if(!matched) return;
    LOG(5, "reg = " << std::dec << reg);

    PointerPageNodeDetection pageDetector;
    pageDetector.detectFor(state, reg);

    bool first = true;
    address_t pageAddr = 0;
    std::vector<Instruction *> pages;

    for(const auto& page : pageDetector.getList()) {
        if(first) {
            pageAddr = page.tree->getValue();
            first = false;
        }
        else {
            if(pageAddr != page.tree->getValue()) {
                LOG(5, "0x" << std::hex << pageAddr
                    << " vs 0x" << page.tree->getValue());
                throw("page address mismatch!");
                break;
            }
        }
        pages.push_back(page.owner->getInstruction());
    }

    if(pages.size() > 0) {
        LOG(5, "pointer found at 0x"
            << std::hex << state->getInstruction()->getAddress());

        address_t addr = pageAddr + offset->getValue();
        LOG(5, "address 0x" << std::hex << addr);

        for(auto p : pages) {
            checkLink(p, addr);
            found[p] = addr;
        }
        checkLink(state->getInstruction(), addr);
        found[state->getInstruction()] = addr;
    }
}

void PointerDetection::checkLink(Instruction *instruction, address_t target) {
    auto semantic = instruction->getSemantic();
    if(auto linked = dynamic_cast<LinkedInstruction *>(semantic)) {
        if(auto link = dynamic_cast<NormalLink *>(linked->getLink())) {
            LOG(5, "original NORMAL link pointing to : 0x"
                << std::hex << link->getTargetAddress());
            if(link->getTargetAddress() != target) {
                LOG(5, "MISMATCH: 0x" << std::hex << link->getTargetAddress()
                    << " vs 0x" << target
                    << " at 0x" << instruction->getAddress());
            }
        }
        else if(auto link = dynamic_cast<DataOffsetLink *>(linked->getLink())) {
            LOG(5, "original DATA link pointing to : 0x"
                << std::hex << link->getTargetAddress());
            if(link->getTargetAddress() != target) {
                LOG(5, "MISMATCH: 0x" << std::hex << link->getTargetAddress()
                    << " vs 0x" << target
                    << " at 0x" << instruction->getAddress());
            }
        }
    }

}


void PointerPageNodeDetection::detectFor(UDState *state, int reg) {
    list.clear();
    if(auto regref = state->getRegRef(reg)) {
        for(auto s : *regref) {
            detectHelper(s, reg);
        }
    }
    else {
        LOG(5, "not in regref " << std::dec << reg);
    }
}

void PointerPageNodeDetection::detectHelper(UDState *state, int reg) {
    LOG(5, "  looking in 0x" << std::hex
        << state->getInstruction()->getAddress()
        << " for definition of " << std::dec << reg);

    for(auto r : seen[state]) {
        if(r == reg) {
            LOG(5, "  seen already");
            return;
        }
    }
    seen[state].push_back(reg);

    auto tree = state->getRegDef(reg);
    if(!tree) return;

    LOG0(5, "  ");
    IF_LOG(5) tree->print(TreePrinter(0, 0));
    LOG(5, "");

    if(auto page = dynamic_cast<TreeNodeAddress *>(tree)) {
        LOG(5, "found page address");
        list.emplace_back(page, state);
    }
    else if(auto regtree = dynamic_cast<TreeNodePhysicalRegister *>(tree)) {
        if(auto regref = state->getRegRef(regtree->getRegister())) {
            for(auto mov : *regref) {
                detectHelper(mov, regtree->getRegister());
            }
        }
    }
    else if(auto deref = dynamic_cast<TreeNodeDereference *>(tree)) {
        MemLocation loadLoc(deref->getChild());
        if(auto memref = state->getMemRef(reg)) {
            for(auto store : *memref) {
                for(auto it = store->getMemDefList().cbegin();
                    it != store->getMemDefList().cend();
                    ++it) {
                    MemLocation storeLoc(it->second);
                    if(loadLoc == storeLoc) {
                        LOG(5, "  stored in 0x" << std::hex
                            << store->getInstruction()->getAddress());

                        if(auto regref = store->getRegRef(it->first)) {
                            for(auto load : *regref) {
                                detectHelper(load, it->first);
                            }
                        }
                        else {
                            LOG(5, " not in regref " << std::dec << it->first);
                        }
                    }
                }
            }
        }
        else {
            LOG(5, " not in memref " << std::dec << reg);
        }
    }
}


