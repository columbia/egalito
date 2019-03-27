#ifndef EGALITO_SHELL2_CODE_H
#define EGALITO_SHELL2_CODE_H

#include <string>
#include <map>
#include "state.h"
#include "command.h"

class FullCommandList {
private:
    std::map<std::string, Command *> commandMap;
public:
    FullCommandList();

    void add(Command *command);
    Command *lookup(const std::string &name) const;
    std::vector<std::string> lookupPrefix(const std::string &prefix) const;
    std::vector<std::string> getCommandList() const;
private:
    bool helpCommand(ShellState &state, ArgumentValueList &args) const;
    bool runCommand1(const char *file, ShellState &state, ArgumentValueList &args) const
        { return runCommandN(file, state, args, {}); }
    bool runCommandN(const char *file, ShellState &state,
        ArgumentValueList &args, std::vector<const char *> extraArgv) const;
};

#endif
