#ifndef EGALITO_ANALYSIS_SLICING_TREE_H
#define EGALITO_ANALYSIS_SLICING_TREE_H

#include <iosfwd>
#include <vector>
#include "chunk/register.h"
#include "types.h"

class TreePrinter {
private:
    int _indent;
    int _splits;
public:
    TreePrinter(int _indent = 1, int _splits = 2)
        : _indent(_indent), _splits(_splits) {}

    TreePrinter nest() const { return TreePrinter(_indent + 1, _splits - 1); }
    std::ostream &stream() const;
    void indent() const;
    bool shouldSplit() const { return _splits > 0; }
};

class TreeNode {
public:
    virtual ~TreeNode() {}
    virtual void print(const TreePrinter &p) const = 0;
};

class TreeNodeConstant : public TreeNode {
private:
    unsigned long value;
public:
    TreeNodeConstant(unsigned long value) : value(value) {}
    unsigned long getValue() const { return value; }
    void setValue(unsigned long value) { this->value = value; }
    virtual void print(const TreePrinter &p) const;
};

class TreeNodeAddress : public TreeNode {
private:
    address_t address;
public:
    TreeNodeAddress(address_t address) : address(address) {}
    address_t getValue() const { return address; }
    void setValue(address_t address) { this->address = address; }
    virtual void print(const TreePrinter &p) const;
};

class TreeNodeRegister : public TreeNode {
private:
    Register reg;
public:
    TreeNodeRegister(int reg) : reg(Register(reg)) {}
    int getRegister() const { return reg; }
    virtual void print(const TreePrinter &p) const;
};
class TreeNodeRegisterRIP : public TreeNodeRegister {
private:
    address_t value;
public:
    TreeNodeRegisterRIP(address_t value)
        : TreeNodeRegister(X86_REG_RIP), value(value) {}
    address_t getValue() const { return value; }
    virtual void print(const TreePrinter &p) const;
};

class TreeNodeUnary : public TreeNode {
private:
    TreeNode *node;
    const char *name;
public:
    TreeNodeUnary(TreeNode *node, const char *name)
        : node(node), name(name) {}
    TreeNode *getChild() const { return node; }
    virtual void print(const TreePrinter &p) const;
};

class TreeNodeDereference : public TreeNodeUnary {
public:
    TreeNodeDereference(TreeNode *node)
        : TreeNodeUnary(node, "deref") {}
};
class TreeNodeJump : public TreeNodeUnary {
public:
    TreeNodeJump(TreeNode *node)
        : TreeNodeUnary(node, "jump") {}
};
class TreeNodeSignExtendByte : public TreeNodeUnary {
public:
    TreeNodeSignExtendByte(TreeNode *node)
        : TreeNodeUnary(node, "sxtb") {}
};
class TreeNodeSignExtendHalfWord : public TreeNodeUnary {
public:
    TreeNodeSignExtendHalfWord(TreeNode *node)
        : TreeNodeUnary(node, "sxtw") {}
};
class TreeNodeSignExtendWord : public TreeNodeUnary {
public:
    TreeNodeSignExtendWord(TreeNode *node)
        : TreeNodeUnary(node, "sxtw") {}
};
class TreeNodeUnsignedExtendWord : public TreeNodeUnary {
public:
    TreeNodeUnsignedExtendWord(TreeNode *node)
        : TreeNodeUnary(node, "uxtw") {}
};

class TreeNodeBinary : public TreeNode {
private:
    TreeNode *left;
    TreeNode *right;
    const char *op;
public:
    TreeNodeBinary(TreeNode *left, TreeNode *right, const char *op)
        : left(left), right(right), op(op) {}
    TreeNode *getLeft() const { return left; }
    TreeNode *getRight() const { return right; }
    const char *getOperator() const { return op; }

    virtual void print(const TreePrinter &p) const;
};

class TreeNodeAddition : public TreeNodeBinary {
public:
    TreeNodeAddition(TreeNode *left, TreeNode *right)
        : TreeNodeBinary(left, right, "+") {}
};
class TreeNodeSubtraction : public TreeNodeBinary {
public:
    TreeNodeSubtraction(TreeNode *left, TreeNode *right)
        : TreeNodeBinary(left, right, "-") {}
};
class TreeNodeMultiplication : public TreeNodeBinary {
public:
    TreeNodeMultiplication(TreeNode *left, TreeNode *right)
        : TreeNodeBinary(left, right, "*") {}
};
class TreeNodeLogicalShiftLeft : public TreeNodeBinary {
public:
    TreeNodeLogicalShiftLeft(TreeNode *left, TreeNode *right)
        : TreeNodeBinary(left, right, "<<") {}
};

class TreeNodeComparison : public TreeNode {
private:
    TreeNode *left;
    TreeNode *right;
public:
    TreeNodeComparison(TreeNode *left, TreeNode *right)
        : left(left), right(right) {}
    TreeNode *getLeft() const { return left; }
    TreeNode *getRight() const { return right; }

    virtual void print(const TreePrinter &p) const;
};

class TreeNodeMultipleParents : public TreeNode {
private:
    std::vector<TreeNode *> parentList;
public:
    void addParent(TreeNode *parent) { parentList.push_back(parent); }

    const std::vector<TreeNode *> &getParents() const { return parentList; }
    virtual void print(const TreePrinter &p) const;
};

#endif
