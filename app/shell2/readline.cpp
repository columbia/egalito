#include <cstring>
#include "readline.h"
#include "code.h"
#include "config.h"

#define HAVE_READLINE

#ifndef HAVE_READLINE
#include <iostream>

Readline::Readline(FullCommandList *commandList) {}
Readline::~Readline() {}

std::string Readline::get(const std::string &prompt) {
    std::cout << prompt;
    std::cout.flush();

    std::string line;
    std::getline(std::cin, line);

    return std::move(line);
}
#else
#include <readline/readline.h>
#include <readline/history.h>

#define HISTORY_FILE ".etshell2_history"

static char **completer(const char *text, int start, int end);
static char *completionGenerator(const char *text, int state);
static FullCommandList *commandList;

Readline::Readline(FullCommandList *commandList) {
    read_history(HISTORY_FILE);
    rl_attempted_completion_function = completer;
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

    char *line = readline(prompt2.c_str());
    if(line && *line) {
        add_history(line);
    }

    std::string lineCpp(line ? line : "quit");
    free(line);
    return std::move(lineCpp);
}

static char **completer(const char *text, int start, int end) {
    rl_attempted_completion_over = 1;  // don't fall back on filename completion

    return rl_completion_matches(text, completionGenerator);
}

static char *completionGenerator(const char *text, int state) {
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

#endif
