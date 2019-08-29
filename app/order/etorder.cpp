#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <cassert>
#include <string>
#include <utility>
#include <cmath>
#include <functional>
#include <cstring>  // for std::strcmp
#include "etorder.h"
#include "conductor/interface.h"
#include "chunk/function.h"
#include "operation/find2.h"

#undef DEBUG_GROUP
#define DEBUG_GROUP load
#include "log/log.h"

static unsigned long getBucket(unsigned long count) {
    return count;
    if(!count) return 0;
    unsigned long value = std::log2l(count);
    return value <= 3 ? 0 : value;
}

static std::vector<Function *> parseOrder(Conductor *conductor, Module *module,
    const std::string &orderFile) {

    std::ifstream file(orderFile.c_str());
    std::string line;
    std::map<Function *, unsigned long> data;
    while(std::getline(file, line)) {
        std::istringstream stream(line);

        unsigned long count = 0;
        std::string nameToken;
        if(stream >> count >> nameToken
            && nameToken[0] == '[' && nameToken[nameToken.length() - 1] == ']') {
            
            nameToken = nameToken.substr(1, nameToken.length() - 2);
            auto f = ChunkFind2(conductor).findFunctionInModule(nameToken.c_str(), module);
            if(f) {
                data.insert(std::make_pair(f, getBucket(count)));
                LOG(0, "count " << f->getName() << " = " << getBucket(count));
            }
        }
    }

    std::map<Function *, unsigned long> input;
    unsigned long index = 0;
    for(auto func : CIter::functions(module)) {
        input.insert(std::make_pair(func, index ++));
    }

    std::vector<Function *> order;
    for(auto func : CIter::functions(module)) order.push_back(func);

    std::sort(order.begin(), order.end(), [&data, &input] (Function *a, Function *b) {
        //return input[a] < input[b];
        auto ad = data.find(a);
        auto bd = data.find(b);
        if(ad != data.end() && bd != data.end()) {
            if((*ad).second < (*bd).second) return false;
            else if((*ad).second > (*bd).second) return true;
        }
        else if(ad != data.end() && (*ad).second) {
            return true;
        }
        else if(bd != data.end() && (*bd).second) {
            return false;
        }
        return input[a] < input[b];
    });
    for(auto f : order) {
        unsigned long count = 0;
        if(data.find(f) != data.end()) count = data[f];
        LOG(1, "    [" << f->getName() << "] index " << std::dec << input[f] << " count " << count);
    }

    return order;
}

static void parse(const std::string &filename, const std::string &orderFile,
    const std::string &output, bool oneToOne, bool quiet) {

    std::cout << "Transforming file [" << filename << "]\n";

    // Set logging levels according to quiet and EGALITO_DEBUG env var.
    EgalitoInterface egalito(/*verboseLogging=*/ !quiet, /*useLoggingEnvVar=*/ true);

    // Parsing ELF files can throw exceptions.
    try {
        egalito.initializeParsing();  // Creates Conductor and Program

        // Parse a filename; if second arg is true, parse shared libraries
        // recursively. This parse() can be called repeatedly to inject other
        // dependencies, and the recursive closure can be parsed with
        // parseRecursiveDependencies() at any later stage.
        std::cout << "Parsing ELF file"
            << (oneToOne ? "" : " and all shared library dependencies") << "...\n";
        auto module = egalito.parse(filename, !oneToOne);

        // This is where transformations, if any, should be applied to program.
        //auto program = egalito.getProgram();

        // Generate output, mirrorgen or uniongen. If only one argument is
        // given to generate(), automatically guess based on whether multiple
        // Modules are present.
        std::cout << "Performing code generation into [" << output << "]...\n";
        assert(oneToOne);

        auto order = parseOrder(egalito.getConductor(), module, orderFile);

        egalito.generate(output, order);

    }
    catch(const char *message) {
        std::cout << "Exception: " << message << std::endl;
    }
}

static void printUsage(const char *program) {
    std::cout << "Usage: " << program << " [options] input-file function-ordering output-file\n"
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
        else if(argv[a] && argv[a + 1] && argv[a + 2]) {
            parse(argv[a], argv[a + 1], argv[a + 2], oneToOne, quiet);
            break;
        }
        else {
            std::cout << "Error: no output filename given!\n";
            break;
        }
    }
    return 0;
}
