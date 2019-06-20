#include <iostream>
#include <string>
#include <functional>
#include <cstring>  // for std::strcmp
#include "etpe.h"
#include "pe/pemap.h"
#include "exefile/exefile.h"
#include "conductor/filetype.h"
#include "conductor/conductor.h"
#include "conductor/interface.h"

static void parse(const std::string &filename, const std::string &symbolFile,
    bool quiet) {

    if(symbolFile.length() > 0) {
        std::cout << "Transforming file [" << filename
            << "] using symbol file [" << symbolFile << "]\n";
    }
    else {
        std::cout << "Transforming file [" << filename << "]\n";
    }

    EgalitoInterface egalito(/*verboseLogging=*/ !quiet, /*useLoggingEnvVar=*/ true);

    try {
        egalito.initializeParsing();  // Creates Conductor and Program
        PEMap *peMap = new PEMap(filename);
        ExeFile *exeFile = new PEExeFile(peMap, filename, filename);

        exeFile->parseSymbolsAndRelocs(symbolFile);

        /*egalito.getConductor()->parseAnythingWithSymbols(filename, symbolFile,
            EXE_PE, Library::ROLE_MAIN);*/
    }
    catch(const char *message) {
        std::cout << "Exception: " << message << std::endl;
    }
}

static void printUsage(const char *program) {
    std::cout << "Usage: " << program << " [options] input-file [csv-symbol-dump]\n"
        "    Transforms an executable to a new ELF file.\n"
        "\n"
        "Options:\n"
        "    -v     Verbose mode, print logging messages\n"
        "    -q     Quiet mode (default), suppress logging messages\n"
        "Note: the EGALITO_DEBUG variable is also honoured.\n";
}

int main(int argc, char *argv[]) {
    if(argc < 3) {
        printUsage(argv[0] ? argv[0] : "etelf");
        return 0;
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
        else if(argv[a] && !argv[a + 1]) {
            parse(argv[a], "", quiet);
            break;
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
