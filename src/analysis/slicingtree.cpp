#include <iostream>  // for std::cout
#include <iomanip>
#include <sstream>
#include <string>
#include <cstring>
#include "slicingtree.h"
#include "disasm/dump.h"

std::ostream &TreePrinter::stream() const {
    return std::cout;
}
void TreePrinter::indent() const {
    stream() << std::string(4*_indent, ' ');
}

void TreeNodeConstant::print(const TreePrinter &p) const {
    p.stream() << std::dec << value;
}

void TreeNodeAddress::print(const TreePrinter &p) const {
    p.stream() << "0x" << std::hex << address;
}

void TreeNodeRegister::print(const TreePrinter &p) const {
    p.stream() << "%" << std::dec << DisasmDump::getRegisterName(reg);
}

void TreeNodeRegisterRIP::print(const TreePrinter &p) const {
    p.stream() << "%rip=0x" << std::hex << value;
}

void TreeNodePhysicalRegister::print(const TreePrinter &p) const {
    p.stream() << "%" << std::dec << reg;
}

void TreeNodeUnary::print(const TreePrinter &p) const {
    p.stream() << "(" << name << " ";
    node->print(p);
    p.stream() << ")";
}

bool TreeNodeUnary::equal(TreeNode *tree) {
    auto t = dynamic_cast<TreeNodeUnary *>(tree);
    return t && !strcmp(name, t->getName()) &&
        getChild()->equal(t->getChild());
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

bool TreeNodeBinary::equal(TreeNode *tree) {
    auto t = dynamic_cast<TreeNodeBinary *>(tree);
    return t && !strcmp(op, t->getOperator()) && (
        (getLeft()->equal(t->getLeft()) &&
         getRight()->equal(t->getRight()))
         ||
        (getRight()->equal(t->getLeft()) &&
          getLeft()->equal(t->getRight())));
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

bool TreeNodeMultipleParents::equal(TreeNode *tree) {
    auto t = dynamic_cast<TreeNodeMultipleParents *>(tree);
    if(t) {
        auto p1 = t->getParents();
        auto p2 = getParents();
        if(p1.size() != p2.size()) {
            return false;
        }

        for(auto t1 = p1.begin(), t2 = p2.begin(); t1 != p1.end(); ++t1, ++t2) {
            if(!(*t1)->equal(*t2)) {
                return false;
            }
        }
        return true;
    }
    return false;
}

TreeFactory& TreeFactory::instance() {
    static TreeFactory factory;
    return factory;
}

TreeNodePhysicalRegister *TreeFactory::makeTreeNodePhysicalRegister(
    Register reg, int width) {

    auto i = regTrees.find(reg);
    if(i != regTrees.end()) {
        return i->second;
    }

    TreeNodePhysicalRegister *n = new TreeNodePhysicalRegister(reg, width);
    regTrees.emplace(reg, n);
    return n;
}

void TreeFactory::clean() {
    for(auto t : trees) { delete t; }
    trees.clear();
}

void TreeFactory::cleanAll() {
    clean();
    for(auto t : regTrees) { delete t.second; }
    regTrees.clear();
}
