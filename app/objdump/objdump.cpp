#include <iostream>
#include <functional>
#include <cstring>  // for std::strcmp
#include "objdump.h"
#include "conductor/conductor.h"
#include "chunk/dump.h"
#include "log/registry.h"
#include "log/temp.h"

void ObjDump::parse(const char *filename) {
    std::cout << "objdump file [" << filename << "]\n";

    if(!options.getDebugMessages()) {
        // Note: once we disable messages, we never re-enable them.
        // Right now the old settings aren't saved so it's not easy to do.
        GroupRegistry::getInstance()->muteAllSettings();
    }

    try {
        if(ElfMap::isElf(filename)) {
            std::cout << "parsing ELF file with recursive="
                << options.getRecursive() << "...\n";
            setup.parseElfFiles(filename, options.getRecursive(), false);
        }
        else {
            std::cout << "parsing archive...\n";
            setup.parseEgalitoArchive(filename);
        }

        TemporaryLogLevel enableDisassemblyOutput1("chunk", 9);
        TemporaryLogLevel enableDisassemblyOutput2("disasm", 9);
        ChunkDumper dumper(options.getShowBasicBlocks());
        setup.getConductor()->acceptInAllModules(&dumper);
    }
    catch(const char *message) {
        std::cout << "Exception: " << message << std::endl;
    }
}

void printUsage(const char *program) {
    std::cout << "Usage: " << program << " [options] file1 file2...\n"
        "    Dumps the code contained in ELF files or Egalito archives.\n"
        "\n"
        "Options:\n"
        "    -d     Ignored for compatibility with GNU objdump\n"
        "    -v     Verbose mode, print logging messages\n"
        "    -q     Quiet mode (default), suppress logging messages\n"
        "    --recursive     Recursively dump shared library dependencies\n"
        "    --no-recursive  Dump only the main ELF/archive file (default)\n"
        "    --basic-blocks     Show basic blocks in output\n"
        "    --no-basic-blocks  Don't split functions into blocks in output\n"
        "\n"
        "Note: the EGALITO_DEBUG variable is also honoured.\n";
}

int main(int argc, char *argv[]) {
    if(argc <= 1) {
        printUsage(argv[0] ? argv[0] : "objdump");
        return 0;
    }

    //GroupRegistry::getInstance()->dumpSettings();
    if(!SettingsParser().parseEnvVar("EGALITO_DEBUG")) {
        printUsage(argv[0]);
        return 1;
    }

    struct {
        const char *str;
        std::function<void (ObjDumpOptions &)> action;
    } actions[] = {
        // -d option ignored for compatibility with GNU objdump
        {"-d", [] (ObjDumpOptions &options) {}},

        // should we show debugging log messages?
        {"-v", [] (ObjDumpOptions &options) {
            options.setDebugMessages(true);
        }},
        {"-q", [] (ObjDumpOptions &options) {
            options.setDebugMessages(false);
        }},

        // should we recursively process all library dependencies?
        {"--recursive", [] (ObjDumpOptions &options) {
            options.setRecursive(true);
        }},
        {"--no-recursive", [] (ObjDumpOptions &options) {
            options.setRecursive(false);
        }},

        // should we show basic blocks in output?
        {"--basic-blocks", [] (ObjDumpOptions &options) {
            options.setShowBasicBlocks(true);
        }},
        {"--no-basic-blocks", [] (ObjDumpOptions &options) {
            options.setShowBasicBlocks(false);
        }},
    };

    ObjDump objdump;
    for(int a = 1; a < argc; a ++) {
        const char *arg = argv[a];
        if(arg[0] == '-') {
            bool found = false;
            for(auto action : actions) {
                if(std::strcmp(arg, action.str) == 0) {
                    action.action(objdump.getOptions());
                    found = true;
                    break;
                }
            }
            if(!found) {
                std::cout << "Warning: unrecognized option \"" << arg << "\"\n";
            }
        }
        else {
            objdump.parse(arg);
        }
    }
    return 0;
}
