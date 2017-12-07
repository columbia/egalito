#ifndef EGALITO_LOAD_CALL_INIT_H
#define EGALITO_LOAD_CALL_INIT_H

class ElfSpace;
class GSTable;
class Conductor;

class CallInit {
private:
    using Start2Type = void (*)();
public:
    static void makeInitArray(ElfSpace *space, int argc, char **argv,
        char **envp, GSTable *gsTable);
    static Start2Type getStart2(Conductor *conductor);
};

#endif
