#include <iostream>
#include <sstream>
#include "command.h"

Arguments Arguments::popFront() {
    Arguments other;
    auto it = args.begin();
    for(it ++; it != args.end(); it ++) {
        other.add(*it);
    }
    return std::move(other);
}

void Arguments::shouldHave(std::size_t count) {
    if(size() != count) {
        std::ostringstream stream;
        stream << "command expects " << count
            << " arguments, but received " << size();
        throw stream.str();
    }
}

void CompositeCommand::add(std::string subcommand, Command *command) {
    commandList[subcommand] = command;
}

bool CompositeCommand::invoke(const std::vector<std::string> &args) {
    if(args.size() == 0) {
        if(invokeNull(args)) return true;

        std::cout << "error: please pass subcommand to \""
            << getName() << "\"\n";
        return false;
    }

    auto command = commandList.find(args[0]);
    if(command != commandList.end()) {
        auto newArgs = args;
        newArgs.erase(newArgs.begin());
        return (*command).second->invoke(newArgs);
    }
    else {
        if(invokeDefault(args)) return true;

        std::cout << "error: no subcommand \"" << args[0]
            << "\" of \"" << getName() << "\"\n";
    }

    return false;
}
