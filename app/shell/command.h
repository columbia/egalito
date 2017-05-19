#ifndef EGALITO_SHELL_COMMAND_H
#define EGALITO_SHELL_COMMAND_H

#include <string>
#include <vector>
#include <map>
#include <functional>
#include "types.h"  // for address_t

class Arguments {
private:
    std::vector<std::string> args;
public:
    void add(const std::string &arg) { args.push_back(arg); }
    Arguments popFront();
    bool asHex(std::size_t index, address_t *address);
    bool asDec(std::size_t index, unsigned long *value);
    void shouldHave(std::size_t count);
    void shouldHaveAtLeast(std::size_t count);

    std::size_t size() const { return args.size(); }
    std::string front() const { return args.front(); }

    std::vector<std::string>::iterator begin() { return args.begin(); }
    std::vector<std::string>::const_iterator begin() const { return args.begin(); }
    std::vector<std::string>::iterator end() { return args.end(); }
    std::vector<std::string>::const_iterator end() const { return args.end(); }
};

class Command {
public:
    virtual ~Command() {}
    virtual std::string getName() const = 0;
    virtual std::string getDescription() const = 0;
    virtual void operator () (Arguments args) = 0;
};

class CommandImpl : public Command {
private:
    std::string name;
    std::string desc;
public:
    CommandImpl(const std::string &name, const std::string &desc)
        : name(name), desc(desc) {}
    virtual std::string getName() const { return name; }
    virtual std::string getDescription() const { return desc; }
};

class FunctionCommand : public CommandImpl {
public:
    typedef std::function<void (Arguments)> FunctionType;
private:
    FunctionType func;
public:
    FunctionCommand(const std::string &name, const FunctionType &func,
        const std::string &desc = "")
        : CommandImpl(name, desc), func(func) {}
    virtual void operator () (Arguments args) { func(args); }
};

class CommandList : public CommandImpl {
public:
    typedef std::map<std::string, Command *> CommandMapType;
private:
    CommandMapType commandMap;
public:
    using CommandImpl::CommandImpl;
    virtual ~CommandList() {}

    CommandMapType &getMap() { return commandMap; }

    void add(Command *command) { commandMap[command->getName()] = command; }
    void add(std::string command, const FunctionCommand::FunctionType &func, const std::string &desc = "")
        { commandMap[command] = new FunctionCommand(command, func, desc); }
    virtual void operator () (Arguments args) = 0;
};

class CompositeCommand : public CommandList {
public:
    using CommandList::CommandList;
    virtual void operator () (Arguments args);
    virtual void invokeNull(Arguments args) {}
    virtual void invokeDefault(Arguments args) {}
};

#endif
