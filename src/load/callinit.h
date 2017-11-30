#ifndef EGALITO_LOAD_CALL_INIT_H
#define EGALITO_LOAD_CALL_INIT_H

class ElfSpace;

class CallInit {
public:
    static void makeInitArray(ElfSpace *space, char **argv);
    static void callInitFunctions(ElfSpace *space, char **argv);
};

#endif
