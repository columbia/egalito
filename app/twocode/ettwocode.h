#ifndef EGALITO_APP_TWOCODE_H
#define EGALITO_APP_TWOCODE_H

#include "conductor/interface.h"

class TwocodeApp {
private:
    bool quiet;
    EgalitoInterface *egalito;
    Module *extraModule;
public:
    TwocodeApp() : quiet(true), extraModule(nullptr) {}
    void run(int argc, char **argv);
    void parse(const std::string &filename, const std::string &extra, bool oneToOne);
    void generate(const std::string &filename, bool oneToOne);
    Program *getProgram() const { return egalito->getProgram(); }
private:
    void doWatching();
    void doTwocode();
};

#endif
