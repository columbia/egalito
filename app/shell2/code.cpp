#include <iomanip>
#include <functional>
#include "code.h"

FullCommandList::FullCommandList() {
    add(new FunctionCommand("quit", ArgumentSpecList({}, {}),
        [] (ShellState &state, ArgumentValueList &args) {

        state.setExiting(true);
        return true;
    }, "quits the shell"));
    add(new FunctionCommand("help", ArgumentSpecList({}, {
        ArgumentSpec(ArgumentSpec::TYPE_STRING)
    }), std::bind(&FullCommandList::helpCommand, this,
        std::placeholders::_1, std::placeholders::_2),
        "prints help about all commands or a specific command"));
    add(new FunctionCommand("wc", ArgumentSpecList({}, {}, 0, true),
        [] (ShellState &state, ArgumentValueList &args) {

        auto in = args.getInStream();
        long lineCount = 0;
        if(in) {
            std::string line;
            while(std::getline(*in, line)) lineCount ++;
        }
        (*args.getOutStream()) << std::dec << lineCount << std::endl;
        return true;
    }, "counts number of lines in input"));
    add(new FunctionCommand("head", ArgumentSpecList({
        {"-n", ArgumentSpec({"-n"}, ArgumentSpec::TYPE_DECIMAL)}
    }, {}, 0, true), [] (ShellState &state, ArgumentValueList &args) {

        auto in = args.getInStream();
        auto out = args.getOutStream();
        long count = args.getNumber("-n", 10);
        std::string line;
        for(long i = 0; i < count && std::getline(*in, line); i ++) {
            (*out) << line << std::endl;
        }
        return true;
    }, "prints the first N lines of output"));
}

void FullCommandList::add(Command *command) {
    commandMap[command->getName()] = command;
}

Command *FullCommandList::lookup(const std::string &name) const {
    auto found = commandMap.find(name);
    return (found != commandMap.end() ? (*found).second : nullptr);
}

std::vector<std::string> FullCommandList::lookupPrefix(
    const std::string &prefix) const {

    std::vector<std::string> matches;
    auto it = commandMap.lower_bound(prefix);
    auto end = commandMap.upper_bound(prefix + "\xff");
    for( ; it != end; it ++) {
        matches.push_back((*it).first);
    }

    return matches;
}

std::vector<std::string> FullCommandList::getCommandList() const {
    std::vector<std::string> list;
    for(const auto &kv : commandMap) {
        list.push_back(kv.first);
    }

    return list;
}

static void printHelpFor(Command *command, std::ostream &out) {
    out << std::left << std::setw(10) << command->getName()
        << " " << command->getDescription() << std::endl;
}

bool FullCommandList::helpCommand(ShellState &state, ArgumentValueList &args) const {
    if(args.getIndexedCount() >= 1) {
        auto name = args.getIndexed(0).getString();
        if(auto command = lookup(name)) {
            printHelpFor(command, *args.getOutStream());
        }
        else {
            (*args.getOutStream()) << "Error: command \""
                << name << "\" does not exist\n";
        }
    }
    else {
        for(const auto &kv : commandMap) {
            printHelpFor(kv.second, *args.getOutStream());
        }
    }
    return true;
}
