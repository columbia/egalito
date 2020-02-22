#ifndef EGALITO_SHELL_READLINE_H
#define EGALITO_SHELL_READLINE_H

#include <string>

class Shell2App;
class FullCommandList;

class Readline {
public:
    Readline(Shell2App *app, FullCommandList *commandList);
    ~Readline();
    std::string get(const std::string &prompt);
};

#endif
