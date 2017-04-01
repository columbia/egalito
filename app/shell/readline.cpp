#include "readline.h"

#define HAVE_READLINE

#ifndef HAVE_READLINE
#include <iostream>

Readline::Readline() {}
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

#define HISTORY_FILE ".etshell_history"

Readline::Readline() {
    read_history(HISTORY_FILE);
    rl_bind_key('\t', rl_abort);  // disable auto-complete
}

Readline::~Readline() {
    write_history(HISTORY_FILE);
}

std::string Readline::get(const std::string &prompt) {
    char *line = readline(prompt.c_str());
    if(line) {
        add_history(line);
    }

    std::string lineCpp(line);
    free(line);
    return std::move(lineCpp);
}
#endif
