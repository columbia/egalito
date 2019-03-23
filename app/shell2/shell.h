#ifndef EGALITO_SHELL2_SHELL_H
#define EGALITO_SHELL2_SHELL_H

#include <iosfwd>
#include "state.h"
#include "command.h"
#include "conductor/interface.h"

class Shell2App {
private:
    EgalitoInterface egalito;
    ShellState state;
    std::map<std::string, Command *> commandMap;
public:
    Shell2App();
    void mainLoop();
private:
    void parseLine(const std::string &line);
    bool parsePhrase(Command *command, std::istream &argStream,
        ArgumentValueList &argList);
    const ArgumentSpec *parseFlag(const std::string &arg, Command *command);
    bool parseFlagValue(const std::string &arg, const ArgumentSpec *spec,
        ArgumentValueList &argList);
    bool parseIndexArg(const std::string &arg,
        std::vector<ArgumentSpec> &indexList, ArgumentValueList &argList);
};

#endif
