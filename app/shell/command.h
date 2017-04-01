#ifndef EGALITO_SHELL_COMMAND_H
#define EGALITO_SHELL_COMMAND_H

#include <string>
#include <vector>
#include <map>
#include <functional>

class Arguments {
private:
    std::vector<std::string> args;
public:
    void add(const std::string &arg) { args.push_back(arg); }
    Arguments popFront();
    void shouldHave(std::size_t count);

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
    virtual bool invoke(const std::vector<std::string> &args) = 0;
};

class CommandImpl : public Command {
private:
    std::string name;
public:
    CommandImpl(const std::string &name) : name(name) {}
    virtual std::string getName() const { return name; }
};

class CompositeCommand : public CommandImpl {
private:
    std::map<std::string, Command *> commandList;
public:
    using CommandImpl::CommandImpl;

    void add(std::string subcommand, Command *command);

    virtual bool invoke(const std::vector<std::string> &args);
    virtual bool invokeNull(const std::vector<std::string> &args)
        { return false; }
    virtual bool invokeDefault(const std::vector<std::string> &args)
        { return false; }
};

template <typename Functor>
class FunctionCommand : public CommandImpl {
private:
    Functor func;
public:
    FunctionCommand(const std::string &name, const Functor &func)
        : CommandImpl(name), func(func) {}
    virtual bool invoke(const std::vector<std::string> &args)
        { return func(args); }
};

#endif
