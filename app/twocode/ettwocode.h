#ifndef EGALITO_APP_TWOCODE_H
#define EGALITO_APP_TWOCODE_H

#include "conductor/interface.h"

class TwocodeApp {
private:
    bool quiet;
    EgalitoInterface *egalito;
public:
    TwocodeApp() : quiet(true) {}
    void run(int argc, char **argv);
    void parse(const std::string &filename, bool oneToOne);
    void generate(const std::string &filename, bool oneToOne);
    Program *getProgram() const { return egalito->getProgram(); }
private:
    void doWatching();
    void doTwocode();
};

#endif
