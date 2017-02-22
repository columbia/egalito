#include <iostream>  // for std::cout
#include <iomanip>
#include <sstream>
#include <string>
#include "slicingtree.h"
#include "disasm/disassemble.h"

std::ostream &TreePrinter::stream() const {
    return std::cout;
}
void TreePrinter::indent() const {
    stream() << std::string(4*_indent, ' ');
}

void TreeNodeConstant::print(const TreePrinter &p) const {
    p.stream() << value;
}

void TreeNodeAddress::print(const TreePrinter &p) const {
    p.stream() << "0x" << std::hex << address;
}

void TreeNodeRegister::print(const TreePrinter &p) const {
    Disassemble::Handle handle(true);
    p.stream() << "%" << cs_reg_name(handle.raw(), reg);
}

void TreeNodeRegisterRIP::print(const TreePrinter &p) const {
    p.stream() << "%rip=0x" << std::hex << value;
}

void TreeNodeUnary::print(const TreePrinter &p) const {
    p.stream() << "(" << name << " ";
    node->print(p);
    p.stream() << ")";
}

void TreeNodeBinary::print(const TreePrinter &p) const {
    if(p.shouldSplit()) {
        p.stream() << "(" << op << "\n";
        p.indent();
        left->print(p.nest());
        p.stream() << "\n";
        p.indent();
        right->print(p.nest());
        p.stream() << ")";
    }
    else {
        p.stream() << "(" << op << " ";
        left->print(p);
        p.stream() << " ";
        right->print(p);
        p.stream () << ")";
    }
}

void TreeNodeComparison::print(const TreePrinter &p) const {
    if(p.shouldSplit()) {
        p.stream() << "(compare\n";
        p.indent();
        left->print(p.nest());
        p.stream() << "\n";
        p.indent();
        right->print(p.nest());
        p.stream() << ")";
    }
    else {
        p.stream() << "(compare ";
        left->print(p);
        p.stream() << " ";
        right->print(p);
        p.stream () << ")";
    }
}

void TreeNodeMultipleParents::print(const TreePrinter &p) const {
    if(p.shouldSplit()) {
        p.stream() << "(MULTIPLE\n";
        for(size_t i = 0; i < parentList.size(); i ++) {
            p.indent();
            if(i) p.stream() << "| ";
            parentList[i]->print(p.nest());
            if(i + 1 < parentList.size()) p.stream() << "\n";
        }
        p.stream() << ")";
    }
    else {
        p.stream() << "(MULTIPLE ";
        for(size_t i = 0; i < parentList.size(); i ++) {
            if(i) p.stream() << " | ";
            parentList[i]->print(p.nest());
        }
        p.stream () << ")";
    }
}
