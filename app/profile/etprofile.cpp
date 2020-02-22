#include <iostream>
#include <fstream>
#include <string>
#include <cstring>  // for std::strlen
#include <cstdio>
#include "elf/elfmap.h"

static void printUsage(const char *program) {
    std::cout << "Usage: " << program << " [options] executable\n"
        "    Summarizes profiling information from profile.data, like gprof.\n"
        "\n"
        "Note: the EGALITO_DEBUG variable is also honoured.\n";
}

int main(int argc, char *argv[]) {
    if(argc < 2) {
        printUsage(argv[0] ? argv[0] : "etprofile");
        return 0;
    }

    ElfMap *elf = new ElfMap(argv[1]);
    auto section = elf->findSection(".profiling");
    auto nameSection = elf->findSection(".profiling.names");

    size_t size = section->getSize();
    char *data = new char [size];
    std::vector<unsigned long> count(size / sizeof(unsigned long));
    std::ifstream file("profile.data");
    while(file.read(data, size)) {
        unsigned long *uldata = reinterpret_cast<unsigned long *>(data);
        for(size_t i = 0; i < size / sizeof(unsigned long); i ++) {
            count[i] += uldata[i];
        }
    }

    char *p = reinterpret_cast<char *>(nameSection->getReadAddress());
    for(size_t i = 0; i < count.size(); i ++) {
        std::printf("%5ld [%s]\n", count[i], p);
        p += std::strlen(p) + 1;
    }

    return 0;
}
