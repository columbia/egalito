#ifndef EGALITO_SYMBOL_H
#define EGALITO_SYMBOL_H

class Symbol {
private:
    const char *name;
    size_t size;
public:
    Symbol(const char *name, size_t size) : name(name), size(size) {}

    const char *getName() const { return name; }
    size_t getSize() const { return size; }
};

class SymbolList {
private:
    std::map<const char *, Symbol *> lookup;
public:
    bool add(Symbol *symbol);
    Symbol *find(const char *name);
};

#endif
