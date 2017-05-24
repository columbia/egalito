#include <iostream>  // for std::cout
#include <iomanip>
#include <sstream>
#include <string>
#include <cstring>
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

bool TreeNodeUnary::canbe(TreeNode *tree) {
    auto t = dynamic_cast<TreeNodeUnary *>(tree);
    return t && !strcmp(name, t->getName()) &&
        getChild()->canbe(t->getChild());
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

bool TreeNodeBinary::canbe(TreeNode *tree) {
    auto t = dynamic_cast<TreeNodeBinary *>(tree);
    return t && !strcmp(op, t->getOperator()) && (
        (getLeft()->canbe(t->getLeft()) &&
         getRight()->canbe(t->getRight()))
         ||
        (getRight()->canbe(t->getLeft()) &&
          getLeft()->canbe(t->getRight())));
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

bool TreeNodeMultipleParents::canbe(TreeNode *tree) {
    auto t = dynamic_cast<TreeNodeMultipleParents *>(tree);
    for(auto p : getParents()) {
        if(p->canbe(t)) {
            //LOG(1, "this includes arg");
            return true;
        }
    }
    if(t) {
        for(auto p1 : t->getParents()) {
            if(p1->canbe(this)) {
                //LOG(1, "arg includes this");
                return true;
            }
            for(auto p2 : getParents()) {
                if(p2->canbe(p1)) {
                    //LOG(1, "arg children includes this children");
                    return true;
                }
            }
        }
    }
    return false;
}

TreeFactory& TreeFactory::instance() {
    static TreeFactory factory;
    return factory;
}

TreeNodeRegister *TreeFactory::makeTreeNodeRegister(Register reg) {
    auto i = regTrees.find(reg);
    if(i != regTrees.end()) {
        return i->second;
    }

    TreeNodeRegister *n = new TreeNodeRegister(reg);
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
