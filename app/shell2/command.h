#ifndef EGALITO_SHELL_COMMAND_H
#define EGALITO_SHELL_COMMAND_H

#include <iosfwd>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <functional>
#include "types.h"  // for address_t
#include "state.h"

class ArgumentSpec {
public:
    enum ArgumentType {
        TYPE_NOTHING,
        TYPE_FLAG,
        TYPE_BOOL,
        TYPE_STRING,
        TYPE_FILENAME,
        TYPE_VARIABLE,
        TYPE_ADDRESS,
        TYPE_HEX,
        TYPE_DECIMAL,
        TYPE_NUMBER,  // hex or decimal
        TYPE_UNSIGNED_NUMBER,  // hex or decimal
        TYPE_CHUNK,
        TYPE_MODULE,
        TYPE_FUNCTION,
        TYPE_ANYTHING
    };
private:
    ArgumentType type;
    std::set<std::string> flagList;  // optional
public:
    ArgumentSpec(ArgumentType type = TYPE_ANYTHING)
        : type(type) {}
    ArgumentSpec(const std::set<std::string> &flagList,
        ArgumentType type = TYPE_ANYTHING)
        : type(type), flagList(flagList) {}

    ArgumentType getType() const { return type; }
    bool hasFlagValue() const
        { return flagList.size() > 0 && type != TYPE_FLAG; }
    bool flagValueMatches(const std::string &data) const;

    bool flagNameMatches(const std::string &data) const;
    const std::string &getCanonicalFlag() const
        { return *flagList.begin(); }
    const std::set<std::string> &getFlagList() const { return flagList; }

    const char *getExpectedMessage() const { return getExpectedMessage(type); }
    static const char *getExpectedMessage(ArgumentType type);
};

class ArgumentSpecList {
private:
    bool supportsInStream;
    std::map<std::string, ArgumentSpec> flagSpec;
    std::vector<ArgumentSpec> indexSpec;
    size_t requiredArguments;
public:
    ArgumentSpecList(const std::map<std::string, ArgumentSpec> &flagSpec,
        const std::vector<ArgumentSpec> &indexSpec,
        size_t requiredArguments = 0, bool supportsInStream = false);

    bool getSupportsInStream() const { return supportsInStream; }
    const std::map<std::string, ArgumentSpec> &getFlagSpecs() const { return flagSpec; }
    const std::vector<ArgumentSpec> &getIndexSpecs() const { return indexSpec; }
    size_t getRequiredArguments() const { return requiredArguments; }
};

class ArgumentValue {
private:
    std::string data;
    ArgumentSpec::ArgumentType type;
public:
    ArgumentValue() : type(ArgumentSpec::TYPE_NOTHING) {}
    ArgumentValue(const std::string &data, ArgumentSpec::ArgumentType type)
        : data(data), type(type) {}
    ArgumentSpec::ArgumentType getType() const { return type; }

    bool exists() const { return type != ArgumentSpec::TYPE_NOTHING; }
    std::string getString() const;
    bool getBool() const;
    address_t getAddress() const;
    long getNumber() const;
    unsigned long getUnsignedNumber() const;
    Chunk *getChunk(ShellState &state) const;
};

class ArgumentValueList {
private:
    std::istream *inStream;
    std::ostream *outStream;
    std::map<std::string, ArgumentValue> flag;
    std::vector<ArgumentValue> indexArg;
public:
    ArgumentValueList() : inStream(nullptr), outStream(nullptr) {}
    void setInStream(std::istream *i) { inStream = i; }
    void setOutStream(std::ostream *o) { outStream = o; }
    std::istream *getInStream() const { return inStream; }
    std::ostream *getOutStream() const { return outStream; }

    void add(const std::string &name, const ArgumentValue &value)
        { flag[name] = value; }
    void addIndexed(const ArgumentValue &value) { indexArg.push_back(value); }

    bool hasArgument(const std::string &name) const;
    bool getBool(const std::string &name, bool defaultValue = false) const;
    std::string getString(const std::string &name,
        const std::string &defaultValue = "") const;
    long getNumber(const std::string &name,
        long defaultValue = 0) const;
    const ArgumentValue &get(const std::string &name,
        const ArgumentValue &defaultValue = ArgumentValue()) const;

    unsigned long getIndexedCount() const { return indexArg.size(); }
    const ArgumentValue &getIndexed(unsigned long index) const
        { return indexArg[index]; }
    const std::vector<ArgumentValue> &getIndexedList() const { return indexArg; }

    void dump();
};

class Command {
public:
    virtual ~Command() {}
    virtual std::string getName() const = 0;
    virtual std::string getDescription() const = 0;
    virtual const ArgumentSpecList &getSpec() const = 0;
    virtual bool operator () (ShellState &state, ArgumentValueList &args) = 0;
};

class CommandImpl : public Command {
private:
    std::string name;
    std::string desc;
    ArgumentSpecList spec;
public:
    CommandImpl(const std::string &name, const std::string &desc,
        ArgumentSpecList spec)
        : name(name), desc(desc), spec(spec) {}
    virtual std::string getName() const { return name; }
    virtual std::string getDescription() const { return desc; }
    virtual const ArgumentSpecList &getSpec() const { return spec; }
    virtual ArgumentSpecList &getSpec() { return spec; }
};

class FunctionCommand : public CommandImpl {
public:
    typedef std::function<bool (ShellState &, ArgumentValueList &args)> FunctionType;
private:
    FunctionType func;
public:
    FunctionCommand(const std::string &name, ArgumentSpecList spec,
        const FunctionType &func, const std::string &desc = "")
        : CommandImpl(name, desc, spec), func(func) {}
    virtual bool operator () (ShellState &state, ArgumentValueList &args)
        { return func(state, args); }
};

#endif
