#include <iostream>
#include <string>
#include <cstring>  // for std::strcmp
#include "etelf.h"
#include "conductor/interface.h"

static void parse(const std::string &filename, const std::string &output,
    bool oneToOne, bool quiet) {

    std::cout << "Transforming file [" << filename << "]\n";

    // Set logging levels according to quiet and EGALITO_DEBUG env var.
    EgalitoInterface egalito(/*verboseLogging=*/ true, /*useLoggingEnvVar=*/ false);
    if(quiet) egalito.muteOutput();
    egalito.parseLoggingEnvVar( /*default*/ );

    // Parsing ELF files can throw exceptions.
    try {
        egalito.initializeParsing();  // Creates Conductor and Program

        // Parse a filename; if second arg is true, parse shared libraries
        // recursively. This parse() can be called repeatedly to inject other
        // dependencies, and the recursive closure can be parsed with
        // parseRecursiveDependencies() at any later stage.
        std::cout << "Parsing ELF file"
            << (oneToOne ? "" : " and all shared library dependencies") << "...\n";
        egalito.parse(filename, !oneToOne);

        // This is where transformations, if any, should be applied to program.
        //auto program = egalito.getProgram();

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
        "    Transforms an executable to a new ELF file.\n"
        "\n"
        "Options:\n"
        "    -m     Perform mirror elf generation (1-1 output)\n"
        "    -u     Perform union elf generation (merged output)\n"
        "    -v     Verbose mode, print logging messages\n"
        "    -q     Quiet mode (default), suppress logging messages\n"
        "Note: the EGALITO_DEBUG variable is also honoured.\n";
}

int main(int argc, char *argv[]) {
    if(argc < 3) {
        printUsage(argv[0] ? argv[0] : "etelf");
        return 0;
    }

    bool oneToOne = true;
    bool quiet = true;

    struct {
        const char *str;
        std::function<void ()> action;
    } actions[] = {
        // which elf gen should we perform?
        {"-m", [&oneToOne] () { oneToOne = true; }},
        {"-u", [&oneToOne] () { oneToOne = false; }},

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
            parse(argv[a], argv[a + 1], oneToOne, quiet);
            break;
        }
        else {
            std::cout << "Error: no output filename given!\n";
            break;
        }
    }
    return 0;
}
