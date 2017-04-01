#ifndef EGALITO_LOAD_CALL_INIT_H
#define EGALITO_LOAD_CALL_INIT_H

class ElfSpace;

class CallInit {
public:
    static void callInitFunctions(ElfSpace *space);
};

#endif
