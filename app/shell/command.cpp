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

bool Arguments::asHex(std::size_t index, address_t *address) {
    const char *str = args[index].c_str();
    char *end = nullptr;
    *address = std::strtol(str, &end, 16);
    return (*str != 0 && *end == 0);
}

void Arguments::shouldHave(std::size_t count) {
    if(size() != count) {
        std::ostringstream stream;
        stream << "command expects " << count
            << " arguments, but received " << size();
        throw stream.str();
    }
}

void CompositeCommand::operator () (Arguments args) {
    if(args.size() == 0) {
        invokeNull(args);
        return;
    }

    auto command = getMap().find(args.front());
    if(command != getMap().end()) {
        (*(*command).second)(args.popFront());
    }
    else {
        invokeDefault(args);
    }
}
