#include <iostream>
#include <functional>
#include <string>
#include <cstring>  // for std::strcmp
#include "ettwocode.h"
#include "chunk/concrete.h"
#include "pass/chunkpass.h"
#include "pass/usegstable.h"
#include "pass/condwatchpoint.h"
#include "pass/twocodevars.h"
#include "log/registry.h"
#include "log/temp.h"

void TwocodeApp::parse(const std::string &filename, bool oneToOne) {
    egalito = new EgalitoInterface(!quiet, true);

    std::cout << "Transforming file [" << filename << "]\n";

    try {
        egalito->initializeParsing();

        if(oneToOne) {
            std::cout << "Parsing ELF file...\n";
        }
        else {
            std::cout << "Parsing ELF file and all shared library dependencies...\n";
        }
        egalito->parse(filename, !oneToOne);
    }
    catch(const char *message) {
        std::cout << "Exception: " << message << std::endl;
    }
}

void TwocodeApp::generate(const std::string &output, bool oneToOne) {
    std::cout << "Performing code generation into [" << output << "]...\n";
    egalito->generate(output, !oneToOne);
}

void TwocodeApp::doWatching() {
    std::cout << "Adding conditional watchpoint...\n";
    auto program = getProgram();
    RUN_PASS(CondWatchpointPass(), program);
    //RUN_PASS(ProfileSavePass(), program);
}

void TwocodeApp::doTwocode() {
    std::cout << "Adding twocode...\n";
    auto program = getProgram();

    auto gsTable = new GSTable();
    auto ifuncList = new IFuncList();
    RUN_PASS(UseGSTablePass(egalito->getConductor(), gsTable, ifuncList, false), program);
    RUN_PASS(TwocodeVarsPass(gsTable, nullptr), program);
}

static void printUsage(const char *program) {
    std::cout << "Usage: " << program << " [options] [mode] input-file output-file\n"
        "    Transforms an executable by adding CFI and a shadow stack.\n"
        "\n"
        "Options:\n"
        "    -v     Verbose mode, print logging messages\n"
        "    -q     Quiet mode (default), suppress logging messages\n"
        "    -m     Perform mirror elf generation (1-1 output)\n"
        "    -u     Perform union elf generation (merged output)\n"
        "\n"
        "Modes:\n"
        "    --twocode          Insert two copies of code\n"
        "Note: the EGALITO_DEBUG variable is also honoured.\n";
}

void TwocodeApp::run(int argc, char **argv) {
    bool oneToOne = true;
    std::vector<std::string> ops;

    const struct {
        const char *str;
        std::function<void ()> action;
    } actions[] = {
        // should we show debugging log messages?
        {"-v", [this] () { quiet = false; }},
        {"-q", [this] () { quiet = true; }},

        // which elf gen should we perform?
        {"-m", [&oneToOne] () { oneToOne = true; }},
        {"-u", [&oneToOne] () { oneToOne = false; }},

        {"--nop",           [&ops] () { }},
        {"--twocode",       [&ops] () { ops.push_back("twocode"); }},
    };

    std::map<std::string, std::function<void ()>> techniques = {
        {"twocode", [this] () { doTwocode(); }},
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
            parse(argv[a], oneToOne);
            for(auto op : ops) {
                techniques[op]();
            }
            generate(argv[a + 1], oneToOne);
            break;
        }
        else {
            std::cout << "Error: no output filename given!\n";
            break;
        }
    }
}

int main(int argc, char *argv[]) {
    if(argc < 3) {
        printUsage(argv[0] ? argv[0] : "ettwocode");
        return 0;
    }

    TwocodeApp app;
    app.run(argc, argv);
    return 0;
}
