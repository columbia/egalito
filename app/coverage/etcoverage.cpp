#include <iostream>
#include <functional>
#include <string>
#include <cstring>  // for std::strcmp
#include "etcoverage.h"
#include "conductor/interface.h"
#include "pass/aflcoverage.h"
#include "pass/ldsorefs.h"
#include "pass/ifuncplts.h"
#include "log/registry.h"
#include "log/temp.h"

static void parse(const std::string& filename, const std::string& output, bool quiet) {
    std::cout << "Instrumenting file [" << filename << "]\n";

    // Set logging levels according to quiet and EGALITO_DEBUG env var.
    EgalitoInterface egalito(/*verboseLogging=*/ !quiet, /*useLoggingEnvVar=*/ true);

    bool oneToOne = false;

    try {
        egalito.initializeParsing();  // Creates Conductor and Program

        // Parse a filename; if second arg is true, parse shared libraries
        // recursively. This parse() can be called repeatedly to inject other
        // dependencies, and the recursive closure can be parsed with
        // parseRecursiveDependencies() at any later stage.
        std::cout << "Parsing ELF file"
            << (oneToOne ? "" : " and all shared library dependencies") << "...\n";
        egalito.parse(filename, !oneToOne);

        std::cout << "Parsing libcoverage.so...\n";
        //setup.addExtraLibraries(std::vector<std::string>{"libcoverage.so"});
        egalito.parse("libcoverage.so", Library::ROLE_EXTRA, false);


        // Apply transformations.
        auto program = egalito.getProgram();
        std::cout << "Adding coverage calls...\n";
        AFLCoveragePass aflCoverage;
        program->accept(&aflCoverage);

        // Generate output, mirrorgen or uniongen. If only one argument is
        // given to generate(), automatically guess based on whether multiple
        // Modules are present.
        std::cout << "Performing code generation into [" << output << "]...\n";
        egalito.generate(output, !oneToOne);
    }
    catch(const char *message) {
        std::cout << "Exception: " << message << std::endl;
    }
}

static void printUsage(const char *program) {
    std::cout << "Usage: " << program << " [options] input-file output-file\n"
        "    Transforms an executable by adding block coverage logging.\n"
        "    Use in conjunction with AFL, set __AFL_SHM_ID env var.\n"
        "\n"
        "Options:\n"
        "    -v     Verbose mode, print logging messages\n"
        "    -q     Quiet mode (default), suppress logging messages\n"
        "Note: the EGALITO_DEBUG variable is also honoured.\n";
}

int main(int argc, char *argv[]) {
    if(argc < 3) {
        printUsage(argv[0] ? argv[0] : "etcoverage");
        return 0;
    }

    if(!SettingsParser().parseEnvVar("EGALITO_DEBUG")) {
        printUsage(argv[0]);
        return 1;
    }

    bool quiet = true;

    struct {
        const char *str;
        std::function<void ()> action;
    } actions[] = {
        // should we show debugging log messages?
        {"-v", [&quiet] () { quiet = false; }},
        {"-q", [&quiet] () { quiet = true; }},
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
            parse(argv[a], argv[a + 1], quiet);
            break;
        }
        else {
            std::cout << "Error: no output filename given!\n";
            break;
        }
    }
    return 0;
}
