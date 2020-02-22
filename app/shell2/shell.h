#ifndef EGALITO_SHELL2_SHELL_H
#define EGALITO_SHELL2_SHELL_H

#include <iosfwd>
#include "state.h"
#include "command.h"
#include "code.h"
#include "passes.h"
#include "conductor/interface.h"

class Shell2App {
private:
    EgalitoInterface egalito;
    ShellState state;
    FullCommandList fullCommandList;
    PassCommands *passCommands;
public:
    Shell2App();
    void mainLoop();

    enum GlobalParseMode {
        GMODE_COMMAND,
        GMODE_FLAG_NAME,
        GMODE_FLAG_VALUE,
        GMODE_INDEX_ARG,
        GMODE_DONE
    };
    struct GlobalParseData {
        std::string partial;
        Command *command;
        const ArgumentSpec *arg;
    };
    GlobalParseMode testParseLine(const std::string &line, GlobalParseData *data);
    ShellState *getState() { return &state; }
public:
    PassCommands *getPassCommands() const { return passCommands; }
private:
    GlobalParseMode testParsePhrase(Command *command, std::istream &argStream,
        ArgumentValueList &argList, bool endsWithSeparator, GlobalParseData *data);
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
