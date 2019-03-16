#ifndef EGALITO_SHELL_READLINE_H
#define EGALITO_SHELL_READLINE_H

#include <string>

class Readline {
public:
    Readline();
    ~Readline();
    std::string get(const std::string &prompt);
};

#endif
