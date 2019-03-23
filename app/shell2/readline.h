#ifndef EGALITO_SHELL_READLINE_H
#define EGALITO_SHELL_READLINE_H

#include <string>

class FullCommandList;

class Readline {
public:
    Readline(FullCommandList *commandList);
    ~Readline();
    std::string get(const std::string &prompt);
};

#endif
