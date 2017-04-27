#include <cstring>  // for strlen
#include "usage.h"
#include "conductor/setup.h"
#include "conductor/conductor.h"
#include "pass/dumptlsinstr.h"
#include "log/registry.h"
#include "log/log.h"

static void otherPasses(ConductorSetup *setup);

int main(int argc, char *argv[]) {
    if(argc < 3) {
        printUsage(argv[0]);
        return -1;
    }

    if(!SettingsParser().parseEnvVar("EGALITO_DEBUG")) {
        printUsage(argv[0]);
        return -2;
    }
    GroupRegistry::getInstance()->dumpSettings();

    LOG(0, "rewriting ELF program [" << argv[1] << "] to [" << argv[2] << "]");

    try {
        ConductorSetup setup;

        setup.parseElfFiles(argv[1], false, false);
        setup.makeFileSandbox(argv[2]);
        otherPasses(&setup);
        setup.moveCode(false);  // calls sandbox->finalize()
    }
    catch(const char *s) {
        LOG(0, "ERROR: " << s);
        std::cerr << "Error: " << s;
        if(*s && s[std::strlen(s) - 1] != '\n') std::cerr << '\n';
        return 1;
    }

    return 0;
}

static void otherPasses(ConductorSetup *setup) {
#if 0
    DumpTLSInstrPass tlsInstr;
    setup->getConductor()->acceptInAllModules(&tlsInstr, true);
    exit(1);
#endif
}
