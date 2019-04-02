#include <iostream>
#include <sstream>
#include "shell.h"
#include "readline.h"
#include "chunks.h"
#include "passes.h"
#include "log/registry.h"

#define DEBUG_GROUP shell
#define D_shell 9
#include "log/log.h"

Shell2App::Shell2App() : fullCommandList(&egalito) {
    // construct commands in FullCommandList

    ChunkCommands chunkCommands(&fullCommandList);
    chunkCommands.construct(&egalito);

    passCommands = new PassCommands(&fullCommandList);
    passCommands->construct(&egalito);
}

void Shell2App::mainLoop() {
    Readline readline(this, &fullCommandList);
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

Shell2App::GlobalParseMode Shell2App::testParseLine(const std::string &line,
    GlobalParseData *data) {

    data->partial = "";
    data->command = nullptr;
    data->arg = nullptr;

    auto comment = line.find('#');
    std::string line2 = (comment == std::string::npos
        ? line : line.substr(0, comment));
    if(line2.length() == 0) {
        return GMODE_COMMAND;
    }

    std::istringstream phraseStream(line2);
    std::string phrase;
    while(std::getline(phraseStream, phrase, '|')) {
        // keep parsing until last phrase
    }

    std::istringstream argStream(phrase);
    std::string commandName;
    if(!(argStream >> commandName)) {
        return GMODE_COMMAND;
    }

    Command *command = fullCommandList.lookup(commandName);
    if(!command) {
        data->partial = commandName;
        return GMODE_COMMAND;
    }
    data->command = command;

    bool endsWithSeparator = (phrase[phrase.length() - 1] == ' ');
    ArgumentValueList argList;
    return testParsePhrase(command, argStream, argList, endsWithSeparator, data);
}

Shell2App::GlobalParseMode Shell2App::testParsePhrase(Command *command,
    std::istream &argStream, ArgumentValueList &argList,
    bool endsWithSeparator, GlobalParseData *data) {

    enum {
        MODE_BEGINNING,
        MODE_BEFORE_FLAG,
        MODE_FLAG_VALUE,
        MODE_BEGIN_INDEX_ARG,
        MODE_INDEX_ARG
    } parseMode = MODE_BEGINNING;
    const ArgumentSpec *currentFlag = nullptr;
    ArgumentSpec prevIndexSpec;
    std::vector<ArgumentSpec> indexSpec = command->getSpec().getIndexSpecs();
    std::string arg;
    while(argStream >> arg) {
        switch(parseMode) {
        case MODE_BEGINNING:
            parseMode = MODE_BEFORE_FLAG;
            // fall-through
        case MODE_BEFORE_FLAG:
            if(arg == "--") {
                parseMode = MODE_BEGIN_INDEX_ARG;
                break;
            }
            if((currentFlag = parseFlag(arg, command))) {
                if(currentFlag->hasFlagValue()) {
                    parseMode = MODE_FLAG_VALUE;
                }
                else {
                    parseFlagValue("", currentFlag, argList);
                }
                break;
            }
            else {
                parseMode = MODE_BEGIN_INDEX_ARG;
                // fall-through
            }
        case MODE_BEGIN_INDEX_ARG:
        case MODE_INDEX_ARG:
            if(!indexSpec.empty()) prevIndexSpec = indexSpec.front();
            if(!parseIndexArg(arg, indexSpec, argList)) {
                if(!endsWithSeparator && arg.length() > 0 && arg[0] == '-') {
                    data->partial = arg;
                    return GMODE_FLAG_NAME;
                }
                if(!indexSpec.empty()) {
                    data->arg = new ArgumentSpec(indexSpec.front());
                    return GMODE_INDEX_ARG;
                }
                return GMODE_DONE;
            }
            parseMode = MODE_INDEX_ARG;
            break;
        case MODE_FLAG_VALUE:
            if(!parseFlagValue(arg, currentFlag, argList)) {
                if(!endsWithSeparator && arg.length() > 0 && arg[0] == '-') {
                    data->partial = arg;
                    return GMODE_FLAG_NAME;
                }
                if(currentFlag->hasFlagValue()) {
                    data->arg = currentFlag;
                    return GMODE_FLAG_VALUE;
                }
                return (indexSpec.empty() ? GMODE_FLAG_NAME : GMODE_INDEX_ARG);
            }
            parseMode = MODE_BEFORE_FLAG;
            break;
        }
    }
    //std::cout << "((" << arg << "))";

    switch(parseMode) {
    case MODE_BEGINNING:
        if(!endsWithSeparator) {
            return GMODE_COMMAND;
        }
        // fall-through
    case MODE_BEFORE_FLAG:
        if(!endsWithSeparator) {
            data->partial = arg;
            data->arg = currentFlag;  // may be null
            return GMODE_FLAG_NAME;
        }
        else if(!indexSpec.empty()) {
            data->arg = new ArgumentSpec(indexSpec.front());
            return GMODE_INDEX_ARG;
        }
        else {
            return GMODE_FLAG_NAME;
        }
    case MODE_BEGIN_INDEX_ARG:
        if(!endsWithSeparator && arg.length() > 0 && arg[0] == '-') {
            data->partial = arg;
            return GMODE_FLAG_NAME;
        }
        // fall-through
    case MODE_INDEX_ARG:
        if(prevIndexSpec.getType() != ArgumentSpec::TYPE_ANYTHING
            && !endsWithSeparator) {

            data->partial = arg;
            data->arg = new ArgumentSpec(prevIndexSpec);  // !!! leaked
            return GMODE_INDEX_ARG;
        }
        else if(!indexSpec.empty()) {
            data->arg = new ArgumentSpec(indexSpec.front());
            return GMODE_INDEX_ARG;
        }
        else {
            return GMODE_DONE;
        }
    case MODE_FLAG_VALUE:
        if(!endsWithSeparator) {
            data->partial = arg;
            data->arg = currentFlag;  // should not be null
            return GMODE_FLAG_VALUE;
        }
        else if(!indexSpec.empty()) {
            data->arg = new ArgumentSpec(indexSpec.front());
            return GMODE_INDEX_ARG;
        }
        else {
            return GMODE_FLAG_NAME;
        }
    }
    return GMODE_DONE;  // should not happen
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

        Command *command = fullCommandList.lookup(commandName);
        if(!command) {
            std::cerr << "Error: unknown command \""
                << commandName << "\", try \"help\"\n";
            return;
        }

        ArgumentValueList argList;
        if(!parsePhrase(command, argStream, argList)) {
            std::cerr << "Error: for command \"" << command->getName()
                << "\": invalid argument\n";
            return;
        }

        commandList.push_back(std::make_pair(command, argList));
    }

    for(size_t i = 1; i < commandList.size(); i ++) {
        Command *command = commandList[i].first;
        if(!command->getSpec().getSupportsInStream()) {
            std::cerr << "Warning: command \"" << command->getName()
                << "\" used after pipe, but does not read input\n";
        }
        //std::cout << "Running \"" << command->getName() << "\" with parameters:\n";
        //commandList[i].second.dump();
    }

    std::istream *inStream = nullptr;
    std::ostream *outStream = nullptr;
    for(size_t i = 0; i < commandList.size(); i ++) {
        Command *command = commandList[i].first;
        ArgumentValueList &argList = commandList[i].second;

        if(i + 1 < commandList.size()) {
            outStream = new std::stringstream();
            LogStream::overrideStream(outStream);
        }
        else {
            outStream = &std::cout;
            LogStream::overrideStream(nullptr);
        }
        argList.setInStream(inStream);
        argList.setOutStream(outStream);

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
    LogStream::overrideStream(nullptr);
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
            if(arg == "--") {
                parseMode = MODE_INDEX_ARG;
                break;
            }
            if((currentFlag = parseFlag(arg, command))) {
                if(currentFlag->hasFlagValue()) {
                    parseMode = MODE_FLAG_VALUE;
                }
                else {
                    parseFlagValue("", currentFlag, argList);
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

    if(!spec->hasFlagValue() || spec->flagValueMatches(arg)) {
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
    if(spec.flagValueMatches(arg)) {
        auto argValue = ArgumentValue(arg, spec.getType());
        argList.addIndexed(argValue);
        indexList.erase(it);
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
