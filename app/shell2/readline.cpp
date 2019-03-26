#include <iostream>
#include <cstring>
#include <signal.h>
#include <setjmp.h>
#include "readline.h"
#include "code.h"
#include "shell.h"
#include "config.h"

#define HAVE_READLINE

#ifndef HAVE_READLINE
#include <iostream>

Readline::Readline(Shell2App *app, FullCommandList *commandList) {}
Readline::~Readline() {}

std::string Readline::get(const std::string &prompt) {
    std::cout << prompt;
    std::cout.flush();

    std::string line;
    std::getline(std::cin, line);

    return std::move(line);
}
#else
#define _FUNCTION_DEF
#include <readline/readline.h>
#include <readline/history.h>

#define HISTORY_FILE ".etshell2_history"

static char **completer(const char *text, int start, int end);
static char *commandCompletionGenerator(const char *text, int state);
static char *flagCompletionGenerator(const char *text, int state);
static char *chunkCompletionGenerator(const char *text, int state);
static Shell2App *app;
static FullCommandList *commandList;
static Shell2App::GlobalParseData parseData;
static bool insideReadline;
static sigjmp_buf jumpBuffer;

static void handleInterrupt(int sig) {
    if(insideReadline) {
        siglongjmp(jumpBuffer, 1);
    }
}

static void registerSIGINTHandler() {
    struct sigaction action;
    std::memset(&action, 0, sizeof(action));
    action.sa_handler = handleInterrupt;
    sigaction(SIGINT, &action, nullptr);
    rl_catch_signals = 1;
    rl_set_signals();  // catch control-c
}

Readline::Readline(Shell2App *app, FullCommandList *commandList) {
    read_history(HISTORY_FILE);
    registerSIGINTHandler();
    rl_attempted_completion_function = completer;
    ::app = app;
    ::commandList = commandList;
    //rl_bind_key('\t', rl_abort);  // disable auto-complete
}

Readline::~Readline() {
    write_history(HISTORY_FILE);
}

#define C_WHITE "37"
#define C_GREEN "32"
#ifndef PROMPT_COLOR
#define PROMPT_COLOR C_WHITE
#endif

#define UNPRINTABLE(text) "\001" text "\002"

std::string Readline::get(const std::string &prompt) {
    std::string prompt2
        = UNPRINTABLE("\033[1;" PROMPT_COLOR "m")
        + prompt
        + UNPRINTABLE("\033[0m");

    while(sigsetjmp(jumpBuffer, 1)) {
        std::cout << std::endl;  // on ctrl-c, go to next line
    }
    insideReadline = true;
    char *line = readline(prompt2.c_str());
    insideReadline = false;
    if(line && *line) {
        add_history(line);
    }
    if(!line) {  // on ctrl-d, print a final newline
        std::cout << std::endl;
    }

    std::string lineCpp(line ? line : "quit");
    free(line);
    return std::move(lineCpp);
}

static char **completer(const char *text, int start, int end) {
    Shell2App::GlobalParseMode mode
        = app->testParseLine(rl_line_buffer, &parseData);

    rl_attempted_completion_over = 1;  // don't fall back on filename completion

    switch(mode) {
    case Shell2App::GMODE_COMMAND:
        return rl_completion_matches(text, commandCompletionGenerator);
    case Shell2App::GMODE_FLAG_NAME:
        return rl_completion_matches(text, flagCompletionGenerator);
    case Shell2App::GMODE_FLAG_VALUE:
    case Shell2App::GMODE_INDEX_ARG:
        switch(parseData.arg->getType()) {
        /*case TYPE_BOOL:
        case TYPE_VARIABLE:
        case TYPE_ADDRESS:
        case TYPE_HEX:
        case TYPE_MODULE:
        case TYPE_FUNCTION:*/
        case ArgumentSpec::TYPE_FILENAME:
            rl_attempted_completion_over = 0;  // fall back on filename completion
            return nullptr;
        case ArgumentSpec::TYPE_CHUNK:
            return rl_completion_matches(text, chunkCompletionGenerator);
        default:
            return nullptr;
        }
    default:
        return nullptr;
    }
}

static char *commandCompletionGenerator(const char *text, int state) {
    static std::vector<std::string> matches;
    static size_t matchIndex = 0;

    if(state == 0) {
        // beginning a new completion, pre-resolve the matches for text
        matches = commandList->lookupPrefix(text);
        matchIndex = 0;
    }

    if(matchIndex >= matches.size()) {
        return nullptr;  // no more matches available
    }
    else {
        // malloc a copy of the match, readline frees it
        return strdup(matches[matchIndex ++].c_str());
    }
}

static bool prefixMatches(const std::string &word, const std::string &prefix) {
    return word.size() >= prefix.size()
        && word.compare(0, prefix.size(), prefix) == 0;
}

static char *flagCompletionGenerator(const char *text, int state) {
    static std::vector<std::string> matches;
    static size_t matchIndex = 0;

    if(state == 0) {
        // beginning a new completion, pre-resolve the matches for text
        matches.clear();
        std::string textString(text);
        if(prefixMatches("--", textString)) {
            matches.push_back("--");
        }
        if(auto command = parseData.command) {
            for(auto kv : command->getSpec().getFlagSpecs()) {
                for(auto alias : kv.second.getFlagList()) {
                    //std::cout << "(" << alias << ")";
                    if(prefixMatches(alias, textString)) {
                        matches.push_back(alias);
                    }
                }
            }
        }

        matchIndex = 0;
    }

    if(matchIndex >= matches.size()) {
        return nullptr;  // no more matches available
    }
    else {
        // malloc a copy of the match, readline frees it
        return strdup(matches[matchIndex ++].c_str());
    }
}

static char *chunkCompletionGenerator(const char *text, int state) {
    static std::vector<std::string> matches;
    static size_t matchIndex = 0;

    if(state == 0) {
        // beginning a new completion, pre-resolve the matches for text
        matches.clear();
        std::string textString(text);
        if(prefixMatches("..", textString)) {
            matches.push_back("..");
        }
        if(auto chunk = app->getState()->getChunk()) {
            if(chunk->getChildren()) {
                for(auto child : chunk->getChildren()->genericIterable()) {
                    if(prefixMatches(child->getName(), textString)) {
                        matches.push_back(child->getName());
                    }
                }
            }
        }

        matchIndex = 0;
    }

    if(matchIndex >= matches.size()) {
        return nullptr;  // no more matches available
    }
    else {
        // malloc a copy of the match, readline frees it
        return strdup(matches[matchIndex ++].c_str());
    }
}

#endif
