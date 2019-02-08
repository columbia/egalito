#include <iostream>
#include <functional>
#include <string>
#include <cstring>  // for std::strcmp
#include "etcet.h"
#include "conductor/conductor.h"
#include "conductor/setup.h"
#include "pass/endbradd.h"
#include "pass/endbrenforce.h"
#include "pass/collapseplt.h"
#include "pass/promotejumps.h"
#include "pass/ldsorefs.h"
#include "pass/ifuncplts.h"
#include "pass/shadowstack.h"
#include "log/registry.h"
#include "log/temp.h"

static void parse(const std::string& filename, const std::string& output, bool quiet, bool gsMode) {
    ConductorSetup setup;
    std::cout << "Transforming file [" << filename << "]\n";

    if(quiet) {
        GroupRegistry::getInstance()->muteAllSettings();
    }

    try {
        if(ElfMap::isElf(filename.c_str())) {
            std::cout << "Parsing ELF file and all shared library dependencies...\n";
            setup.parseElfFiles(filename.c_str(), /*recursive=*/ true, false);
        }
        else {
            std::cout << "Parsing archive...\n";
            setup.parseEgalitoArchive(filename.c_str());
        }

        auto program = setup.getConductor()->getProgram();

        setup.addExtraLibraries(std::vector<std::string>{"libcet.so"});

        std::cout << "Adding shadow stack...\n";
        ShadowStackPass shadowStack(gsMode
            ? ShadowStackPass::MODE_GS : ShadowStackPass::MODE_CONST);
        program->accept(&shadowStack);

        std::cout << "Adding endbr CFI...\n";
        EndbrAddPass endbradd;
        program->accept(&endbradd);

        EndbrEnforcePass endbrEnforce;
        program->accept(&endbrEnforce);

        std::cout << "Preparing for codegen...\n";
        CollapsePLTPass collapsePLT(setup.getConductor());
        program->accept(&collapsePLT);

        PromoteJumpsPass promoteJumps;
        program->accept(&promoteJumps);

        // generate static executable.
        {
            std::cout << "Generating executable [" << output << "]...\n";
            LdsoRefsPass ldsoRefs;
            program->accept(&ldsoRefs);
            IFuncPLTs ifuncPLTs;
            program->accept(&ifuncPLTs);

            setup.generateStaticExecutable(output.c_str());
        }
    }
    catch(const char *message) {
        std::cout << "Exception: " << message << std::endl;
    }
}

static void printUsage(const char *program) {
    std::cout << "Usage: " << program << " [options] input-file output-file\n"
        "    Transforms an executable by adding CFI and a shadow stack.\n"
        "\n"
        "Options:\n"
        "    -v     Verbose mode, print logging messages\n"
        "    -q     Quiet mode (default), suppress logging messages\n"
        "    -g     GS shadow stack implementation\n"
        "    -c     Constant offset shadow stack implementation\n"
        "Note: the EGALITO_DEBUG variable is also honoured.\n";
}

int main(int argc, char *argv[]) {
    if(argc < 3) {
        printUsage(argv[0] ? argv[0] : "etcet");
        return 0;
    }

    if(!SettingsParser().parseEnvVar("EGALITO_DEBUG")) {
        printUsage(argv[0]);
        return 1;
    }

    bool quiet = true;
    bool gsMode = true;

    struct {
        const char *str;
        std::function<void ()> action;
    } actions[] = {
        // should we show debugging log messages?
        {"-v", [&quiet] () { quiet = false; }},
        {"-q", [&quiet] () { quiet = true; }},
        // should we show debugging log messages?
        {"-g", [&gsMode] () { gsMode = true; }},
        {"-c", [&gsMode] () { gsMode = false; }},
    };

    for(int a = 1; a < argc; a ++) {
        const char *arg = argv[a];
        if(arg[0] == '-') {
            bool found = false;
            for(auto action : actions) {
                if(std::strcmp(arg, action.str) == 0) {
                    action.action();
                    found = true;
                    break;
                }
            }
            if(!found) {
                std::cout << "Warning: unrecognized option \"" << arg << "\"\n";
            }
        }
        else if(argv[a] && argv[a + 1]) {
            parse(argv[a], argv[a + 1], quiet, gsMode);
            break;
        }
        else {
            std::cout << "Error: no output filename given!\n";
            break;
        }
    }
    return 0;
}
