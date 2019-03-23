#include <iostream>
#include <sstream>
#include "shell.h"
#include "readline.h"
#include "log/registry.h"

Shell2App::Shell2App() {
    commandMap["quit"] = new FunctionCommand("quit", ArgumentSpecList({}, {}),
        [] (ShellState &state, ArgumentValueList &args) {

        state.setExiting(true);
        return true;
    }, "quits the shell");
}

void Shell2App::mainLoop() {
    Readline readline;
    while(!state.isExiting()) {
        std::ostringstream prompt;
        if(!state.getChunk()) prompt << "egalito> ";
        else {
            prompt << "egalito:[" << state.getChunk()->getName() << "]> ";
        }

        std::string line = readline.get(prompt.str());
        parseLine(line);
    }
}

void Shell2App::parseLine(const std::string &line) {
    auto comment = line.find('#');
    std::string line2 = (comment == std::string::npos
        ? line : line.substr(0, comment));
    if(line2.length() == 0) return;

    std::vector<std::pair<Command *, ArgumentValueList>> commandList;
    std::istringstream phraseStream(line2);
    std::string phrase;
    while(std::getline(phraseStream, phrase, '|')) {
        std::istringstream argStream(phrase);
        std::string commandName;
        if(!(argStream >> commandName)) {
            std::cerr << "Error: no command given, try \"help\"\n";
            return;
        }

        auto commandIterator = commandMap.find(commandName);
        if(commandIterator == commandMap.end()) {
            std::cerr << "Error: unknown command \""
                << commandName << "\", try \"help\"\n";
            return;
        }
        Command *command = (*commandIterator).second;

        ArgumentValueList argList;
        if(!parsePhrase(command, argStream, argList)) {
            std::cerr << "Error: for command \"" << command->getName()
                << "\": invalid argument\n";
            return;
        }

        commandList.push_back(std::make_pair(command, argList));
    }

    std::istream *inStream = nullptr;
    std::ostream *outStream = nullptr;
    for(size_t i = 0; i < commandList.size(); i ++) {
        Command *command = commandList[i].first;
        ArgumentValueList &argList = commandList[i].second;

        if(i + 1 < commandList.size()) {
            outStream = new std::stringstream();
        }
        else {
            outStream = &std::cout;
        }

        try {
            if(!(*command)(state, argList)) {
                // error running command
                break;
            }
        }
        catch(const char *s) {
            std::cout << "Exception: " << s << std::endl;
            break;
        }
        catch(const std::string &s) {
            std::cout << "Exception: " << s << std::endl;
            break;
        }

        if(i + 1 < commandList.size()) {
            delete inStream;
            inStream = static_cast<std::stringstream *>(outStream);
        }
    }
    delete inStream;
    if(outStream != &std::cout) delete outStream;
}

bool Shell2App::parsePhrase(Command *command, std::istream &argStream,
    ArgumentValueList &argList) {

    enum {
        MODE_BEFORE_FLAG,
        MODE_FLAG_VALUE,
        MODE_INDEX_ARG
    } parseMode = MODE_BEFORE_FLAG;
    const ArgumentSpec *currentFlag = nullptr;
    std::vector<ArgumentSpec> indexSpec = command->getSpec().getIndexSpecs();
    size_t indexArgumentsParsed = 0;
    std::string arg;
    while(argStream >> arg) {
        switch(parseMode) {
        case MODE_BEFORE_FLAG:
            if((currentFlag = parseFlag(arg, command))) {
                if(currentFlag->hasFlagValue()) {
                    parseMode = MODE_FLAG_VALUE;
                }
                break;
            }
            else {
                parseMode = MODE_INDEX_ARG;
                // fall-through
            }
        case MODE_INDEX_ARG:
            if(!parseIndexArg(arg, indexSpec, argList)) {
                //printError(currentFlag->getExpectedMessage());
                return false;
            }
            indexArgumentsParsed ++;
            break;
        case MODE_FLAG_VALUE:
            if(!parseFlagValue(arg, currentFlag, argList)) {
                //printError(currentFlag->getExpectedMessage());
                return false;
            }
            parseMode = MODE_BEFORE_FLAG;
            break;
        }
    }

    if(indexArgumentsParsed < command->getSpec().getRequiredArguments()) {
        return false;
    }
    return true;
}

const ArgumentSpec *Shell2App::parseFlag(const std::string &arg,
    Command *command) {

    const auto &specList = command->getSpec();
    for(const auto &kv : specList.getFlagSpecs()) {
        const auto &spec = kv.second;
        if(spec.flagNameMatches(arg)) {
            return &spec;
        }
    }
    return nullptr;
}

bool Shell2App::parseFlagValue(const std::string &arg, const ArgumentSpec *spec,
    ArgumentValueList &argList) {

    if(spec->flagValueMatches(arg)) {
        auto argValue = ArgumentValue(arg, spec->getType());
        argList.add(spec->getCanonicalFlag(), argValue);
        return true;
    }
    return false;
}

bool Shell2App::parseIndexArg(const std::string &arg,
    std::vector<ArgumentSpec> &indexList, ArgumentValueList &argList) {

    auto it = indexList.begin();
    if(it == indexList.end()) return false;
    auto spec = *it;
    indexList.erase(it);
    if(spec.flagValueMatches(arg)) {
        auto argValue = ArgumentValue(arg, spec.getType());
        argList.addIndexed(argValue);
        return true;
    }
    return false;
}

#ifndef GIT_VERSION
    #define GIT_VERSION (unknown)
#endif

#define _STRINGIZE(x) # x
#define _STRINGIZE2(x) _STRINGIZE(x)

int main(int argc, char *argv[]) {
    SettingsParser().parseEnvVar("EGALITO_DEBUG");

    std::cout << "Welcome to the egalito shell2 version "
        << _STRINGIZE2(GIT_VERSION) << ". Type \"help\" for usage.\n";
    Shell2App app;
    app.mainLoop();

    return 0;
}
