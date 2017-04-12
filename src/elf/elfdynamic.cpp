#include <fstream>
#include <sstream>
#include <cstdlib>
#include <elf.h>
#include <glob.h>

#include "elfdynamic.h"
#include "elfmap.h"
#include "log/log.h"

void ElfDynamic::parse(ElfMap *elf) {

    auto dynamic = (elf->getSectionReadPtr<unsigned long *>(".dynamic"));
    if(!dynamic) return;  // statically linked
    auto strtab = elf->getDynstrtab();

    LOG(1, "examining dependencies for ELF file");

    for(unsigned long *pointer = dynamic; *pointer != DT_NULL; pointer += 2) {
        unsigned long type = pointer[0];
        unsigned long value = pointer[1];

        if(type == DT_NEEDED) {
            auto library = strtab + value;
            LOG(1, "    depends on shared library [" << library << "]");
            dependencyList.push_back(library);
        }
        else if(type == DT_RPATH) {
            this->rpath = strtab + value;
            LOG(1, "    rpath [" << rpath << "]");
        }
    }

    resolveLibraries();
}

template<typename Out>
static void split(const std::string &s, char delim, Out result) {
    std::stringstream ss;
    ss.str(s);
    std::string item;
    while(std::getline(ss, item, delim)) {
        *(result++) = item;
    }
}

std::vector<std::string> ElfDynamic::doGlob(std::string pattern) {
    std::vector<std::string> output;
    glob_t list;
    glob(pattern.c_str(), 0, NULL, &list);

    for(size_t i = 0; i < list.gl_pathc; i ++) {
        output.push_back(list.gl_pathv[i]);
    }

    globfree(&list);
    return std::move(output);
}

void ElfDynamic::parseLdConfig(std::string filename,
    std::vector<std::string> &searchPath) {

    std::ifstream file(filename.c_str());
    std::string line;
    while(std::getline(file, line)) {
        if(line.size() == 0) continue;
        if(line[0] == '#') continue;

        std::vector<std::string> tokens;
        split(line, ' ', std::back_inserter(tokens));
        if(tokens.size() == 0) continue;
        else if(tokens.size() == 1) {
            searchPath.push_back(tokens[0]);
        }
        else if(tokens[0] == "include") {
            std::vector<std::string> files = doGlob(tokens[1]);
            for(auto f : files) {
                parseLdConfig(f, searchPath);
            }
        }
        else {
            LOG(0, "Unrecognized line in LD config: [" << line << "]");
        }
    }
}

bool ElfDynamic::isValidElf(std::ifstream &file) {
    Elf64_Ehdr header;
    file.read((char *)&header, sizeof(header));
    
    // make sure this is an ELF file
    if(*(Elf64_Word *)&header != *(Elf64_Word *)ELFMAG) {
        return false;
    }

    // check architecture type
    char type = ((char *)&header)[EI_CLASS];
    if(type != ELFCLASS64) {
        return false;
    }

    return true;
}

void ElfDynamic::resolveLibraries() {
    std::vector<std::string> searchPath;

    const char *egalito_library_path = getenv("EGALITO_LIBRARY_PATH");
    if(egalito_library_path) {
        split(egalito_library_path, ':', std::back_inserter(searchPath));
    }

    if(rpath) {
        split(rpath, ':', std::back_inserter(searchPath));
    }

    const char *ld_library_path = getenv("LD_LIBRARY_PATH");
    if(ld_library_path) {
        split(ld_library_path, ':', std::back_inserter(searchPath));
    }

    parseLdConfig("/etc/ld.so.conf", searchPath);
    searchPath.push_back("/lib");
    searchPath.push_back("/usr/lib");
    searchPath.push_back("/lib64");
    searchPath.push_back("/usr/lib64");

    for(auto &library : dependencyList) {
        if(library[0] == '/') {
            LOG(1, "    library at [" << library << "]");
            processLibrary(library, library.substr(library.rfind('/') + 1));
            continue;
        }

        bool found = false;
        for(auto path : searchPath) {
            LOG(2, "        search [" << path << "]");
            std::string fullPath = path + "/" + library;
            std::ifstream file(fullPath);
            if(file.is_open() && isValidElf(file)) {
                file.close();
                LOG(1, "    library at [" << fullPath << "]");
                processLibrary(fullPath, library);
                found = true;
                break;
            }
        }
        if(!found) {
            LOG(0, "WARNING: can't find shared library [" << library << "] in search path");
        }
    }
}

void ElfDynamic::processLibrary(const std::string &fullPath,
    const std::string &filename) {

    if(libraryList->contains(fullPath)) return;
    if(filename == "ld-linux-x86-64.so.2") {
        LOG(2, "    skipping processing of ld.so for now");
        return;
    }

    LOG(2, "    process [" << fullPath << "] a.k.a. " << filename);

    ElfMap *elf = new ElfMap(fullPath.c_str());

    auto library = new SharedLib(fullPath, filename, elf);
    libraryList->add(library);

    LOG(2, "    added new library [" << filename << "]");
}
