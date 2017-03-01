#ifndef EGALITO_INTEGRATION_JUMP_TABLE_H
#define EGALITO_INTEGRATION_JUMP_TABLE_H

class Function;

class JumpTableIntegration {
public:
    static void run();
    static void run2();
private:
    static bool testFunction(Function *f, int expected);
};

#endif
