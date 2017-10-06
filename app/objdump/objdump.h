#ifndef EGALITO_APP_OBJDUMP_H
#define EGALITO_APP_OBJDUMP_H

#include "conductor/setup.h"

class ObjDumpOptions {
private:
    bool debugMessages = false;
    bool showBasicBlocks = false;
    bool recursive = false;
public:
    bool getDebugMessages() const { return debugMessages; }
    bool getRecursive() const { return recursive; }
    bool getShowBasicBlocks() const { return showBasicBlocks; }

    void setDebugMessages(bool d) { debugMessages = d; }
    void setRecursive(bool r) { recursive = r; }
    void setShowBasicBlocks(bool s) { showBasicBlocks = s; }
};

class ObjDump {
private:
    ObjDumpOptions options;
    ConductorSetup setup;
public:
    void parse(const char *filename);

    ObjDumpOptions &getOptions() { return options; }
};

#endif
